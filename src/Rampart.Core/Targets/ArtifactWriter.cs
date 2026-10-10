using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Rampart.Targets;

public sealed record OutputArtifact(string Path, byte[] Bytes);

/// <summary>Stages a complete output set before promoting any file. An individual
/// file is atomically replaced; failures restore earlier files from private backups.</summary>
public static class ArtifactWriter
{
    public static void Write(IReadOnlyList<OutputArtifact> artifacts, bool overwrite, IEnumerable<string>? protectedInputs = null) =>
        Write(artifacts, overwrite, protectedInputs, removalPaths: null);

    public static void Write(IReadOnlyList<OutputArtifact> artifacts, bool overwrite, IEnumerable<string>? protectedInputs,
        IEnumerable<string>? removalPaths)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var forbidden = new HashSet<string>((protectedInputs ?? []).Select(CanonicalPath), comparer);
        var paths = new HashSet<string>(comparer);
        var admitted = new List<(OutputArtifact? Artifact, string Path, bool Existed)>();
        // Validate the whole set before creating even a temporary file. Resolve
        // directory aliases once, then write through the resolved path so a
        // junction spelling cannot select one of the protected input files.
        foreach (var artifact in artifacts)
        {
            ArgumentNullException.ThrowIfNull(artifact);
            ArgumentNullException.ThrowIfNull(artifact.Bytes);
            string path = CanonicalPath(artifact.Path);
            if (!paths.Add(path) || forbidden.Contains(path))
                throw new IOException("RP_OUTPUT_COLLISION: An output path overlaps an input or another output.");
            string directory = System.IO.Path.GetDirectoryName(path)!;
            if (!Directory.Exists(directory))
                throw new DirectoryNotFoundException("RP_OUTPUT_DIRECTORY: The output directory does not exist.");
            if (Directory.Exists(path))
                throw new IOException("RP_OUTPUT_DIRECTORY: An output path identifies a directory.");
            bool existed = File.Exists(path);
            if (existed && !overwrite)
                throw new IOException("RP_OUTPUT_EXISTS: An output already exists. Enable replacement to overwrite it.");
            admitted.Add((artifact, path, existed));
        }
        foreach (string removal in removalPaths ?? [])
        {
            string path = CanonicalPath(removal);
            if (!paths.Add(path) || forbidden.Contains(path))
                throw new IOException("RP_OUTPUT_COLLISION: An output removal overlaps an input or another output.");
            if (!Directory.Exists(System.IO.Path.GetDirectoryName(path)))
                throw new DirectoryNotFoundException("RP_OUTPUT_DIRECTORY: The output directory does not exist.");
            if (Directory.Exists(path))
                throw new IOException("RP_OUTPUT_DIRECTORY: An output removal identifies a directory.");
            if (!File.Exists(path)) continue;
            if (!overwrite)
                throw new IOException("RP_OUTPUT_EXISTS: An output already exists. Enable replacement to remove it.");
            admitted.Add((null, path, true));
        }
        var staged = new List<(string Path, string? Temporary, string Backup, bool Existed)>();
        int promoted = 0;
        bool committed = false;
        try
        {
            foreach (var (artifact, path, existed) in admitted)
            {
                string directory = System.IO.Path.GetDirectoryName(path)!;
                string temporary = System.IO.Path.Combine(directory, ".rampart-" + Guid.NewGuid().ToString("N") + ".tmp");
                string backup = temporary + ".bak";
                staged.Add((path, artifact is null ? null : temporary, backup, existed));
                if (artifact is null) continue;
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(artifact.Bytes);
                    stream.Flush(flushToDisk: true);
                }
            }
            foreach (var entry in staged)
            {
                // Replace creates the rollback copy and swaps the output in one
                // filesystem operation; the old valid file never disappears first.
                // An obsolete companion file is renamed into its rollback copy.
                // Its bytes are deleted only after the whole output set commits.
                if (entry.Temporary is null)
                    File.Move(entry.Path, entry.Backup, overwrite: false);
                else if (entry.Existed)
                    File.Replace(entry.Temporary, entry.Path, entry.Backup);
                else
                    File.Move(entry.Temporary, entry.Path, overwrite: false);
                promoted++;
            }
            committed = true;
        }
        catch (Exception failure)
        {
            var recoveryFailures = new List<Exception>();
            for (int index = promoted - 1; index >= 0; index--)
            {
                var entry = staged[index];
                try
                {
                    if (entry.Existed)
                        RecoverFile(() => File.Move(entry.Backup, entry.Path, overwrite: true));
                    else
                        RecoverFile(() => File.Delete(entry.Path));
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    // One locked destination must not prevent recovery of the
                    // remaining files. Its backup remains available for recovery.
                    recoveryFailures.Add(error);
                }
            }
            if (recoveryFailures.Count != 0)
                throw new IOException("RP_OUTPUT_RECOVERY: Output promotion failed and some files could not be restored; private backup files were retained.",
                    new AggregateException([failure, .. recoveryFailures]));
            throw;
        }
        finally
        {
            foreach (var entry in staged)
            {
                if (entry.Temporary is not null) TryDelete(entry.Temporary);
                // If rollback itself failed, preserve backups for recovery.
                if (committed) TryDelete(entry.Backup);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try { RecoverFile(() => File.Delete(path)); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // Cleanup cannot undo a successful commit or hide the original
            // promotion failure. An inaccessible private file is left recoverable.
        }
    }

    private static void RecoverFile(Action operation)
    {
        // A scanner can briefly hold a newly promoted image without delete sharing.
        // Retrying only Windows sharing/lock failures lets rollback restore the old
        // set; permanent errors still retain the backup and surface recovery failure.
        // Promotion is not retried: a failed Replace can have partially moved files.
        for (int attempt = 0; ; attempt++)
        {
            try { operation(); return; }
            catch (IOException error) when (OperatingSystem.IsWindows() && attempt < 19
                && (error.HResult & 0xffff) is 32 or 33)
            { Thread.Sleep(25); }
        }
    }

    private static string CanonicalPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string full = System.IO.Path.GetFullPath(path);
        if (OperatingSystem.IsWindows())
        {
            // Win32 normalizes trailing dots/spaces and accepts streams/device
            // names. Reject those ambiguous spellings before comparing paths.
            if (full.StartsWith("\\\\?\\", StringComparison.Ordinal) || full.StartsWith("\\\\.\\", StringComparison.Ordinal))
                throw new IOException("RP_OUTPUT_PATH: Device namespace paths are not accepted for artifacts.");
            string root = System.IO.Path.GetPathRoot(full)!;
            foreach (string part in full[root.Length..].Split(System.IO.Path.DirectorySeparatorChar))
            {
                if (part.EndsWith('.') || part.EndsWith(' ') || part.Contains(':'))
                    throw new IOException("RP_OUTPUT_PATH: An artifact path uses an ambiguous filename or alternate stream.");
                string stem = part.Split('.')[0].TrimEnd(' ');
                if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
                    || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)
                    || stem.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) || stem.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase)
                    || stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                        && (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³'))
                    throw new IOException("RP_OUTPUT_PATH: Device filenames are not accepted for artifacts.");
            }
            if (File.Exists(full) || Directory.Exists(full)) return ResolveWindowsPath(full);
            string? parent = System.IO.Path.GetDirectoryName(full);
            return parent is not null && Directory.Exists(parent)
                ? System.IO.Path.Combine(ResolveWindowsPath(parent), System.IO.Path.GetFileName(full)) : full;
        }
        // Non-Windows callers can use the same writer. Resolve existing symbolic
        // parent directories with a bounded walk instead of treating their text
        // as the identity of the destination.
        string current = System.IO.Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(System.IO.Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = System.IO.Path.Combine(current, part);
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            if (info.Exists && info.LinkTarget is not null)
                current = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName
                    ?? throw new IOException("RP_OUTPUT_PATH: An artifact link could not be resolved.");
        }
        return current;
    }

    private static string ResolveWindowsPath(string path)
    {
        // Opening for attributes follows symbolic links/junctions and expands
        // 8.3 aliases without requesting write access to either an input or output.
        using SafeFileHandle handle = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new IOException("RP_OUTPUT_PATH: An artifact path could not be resolved.", new Win32Exception(Marshal.GetLastWin32Error()));
        var buffer = new StringBuilder(512);
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length >= buffer.Capacity)
        {
            if (length > 32768) throw new IOException("RP_OUTPUT_PATH: An artifact path exceeds the supported length.");
            buffer.Capacity = checked((int)length + 1);
            length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        }
        if (length == 0 || length >= buffer.Capacity)
            throw new IOException("RP_OUTPUT_PATH: An artifact path could not be resolved.", new Win32Exception(Marshal.GetLastWin32Error()));
        string resolved = buffer.ToString();
        return resolved.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase) ? "\\\\" + resolved[8..]
            : resolved.StartsWith("\\\\?\\", StringComparison.Ordinal) ? resolved[4..] : resolved;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
