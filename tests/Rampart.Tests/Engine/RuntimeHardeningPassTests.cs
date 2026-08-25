using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class RuntimeHardeningPassTests
{
    private static readonly string[] RuntimeKnobs =
    [
        "anti-inject.dacl-hardening",
        "anti-inject.cet-shadow-stack",
        "anti-inject.dynamic-code-policy",
        "anti-inject.iat-hash-check",
        "integrity.kernel-wall",
        "integrity.measurement-channels",
        "integrity.tls-veh-ownership",
        "integrity.mitigation-stack",
        "response.silent-taint",
        "response.tool-response",
        "response.brand-overlay",
        "response.custom-messages",
    ];

    [Fact]
    public void SharedDetectionStateIsUniqueAndAccumulatesEnabledChecks()
    {
        BuildContext context = BuildContext(CreateSettings());

        RuntimeDetectionStateLayout first = RuntimeDetectionState.Ensure(context);
        RuntimeDetectionState.Enable(context, RuntimeDetectionKind.CodeModified);
        RuntimeDetectionState.Enable(context, RuntimeDetectionKind.IatModified);
        RuntimeDetectionStateLayout second = RuntimeDetectionState.Ensure(context);

        Assert.Same(first, second);
        Assert.Equal("RMPSTATE", Encoding.ASCII.GetString(context.Pe.ReadRva(first.Rva, 8)));
        Assert.Equal((uint)RuntimeDetectionStateLayout.RecordSize,
            BinaryPrimitives.ReadUInt32LittleEndian(context.Pe.ReadRva(
                first.Rva + RuntimeDetectionStateLayout.SizeOffset, 4)));
        ulong enabled = BinaryPrimitives.ReadUInt64LittleEndian(context.Pe.ReadRva(
            first.Rva + RuntimeDetectionStateLayout.EnabledChecksOffset, 8));
        Assert.Equal(
            RuntimeDetectionKind.CodeModified | RuntimeDetectionKind.IatModified,
            (RuntimeDetectionKind)enabled);
    }

    [Fact]
    public void DetectionEmitterUsesAtomicBitClaimAndSessionTaint()
    {
        var assembler = new Asm();
        RuntimeDetectionState.EmitRecord(
            assembler,
            Reg.R15,
            RuntimeDetectionKind.ForeignModuleObserved,
            taintSession: true,
            taintConstant: 0x1122_3344_5566_7788,
            labelPrefix: "foreign_module");

        byte[] code = assembler.Assemble();
        Assert.Equal(new byte[] { 0xF0, 0x49, 0x0F, 0xBA, 0x6F, 0x18, 0x06 }, code[..7]);
        Assert.True(Contains(code, new byte[] { 0xF0, 0x49, 0x31, 0x4F, 0x20 }));
    }

    [Fact]
    public void RuntimeFeaturesEmitPoliciesIntegrityStateAndResponsePayloads()
    {
        ProtectionSettings settings = CreateSettings();
        BuildContext context = BuildContext(settings);
        var pass = new RuntimeHardeningPass();

        pass.RunBeforeEntryPoint(context);
        new EntryPointPass().Run(context);
        pass.RunAfterEntryPoint(context);
        RelocBuilder.Rebuild(context);

        byte[] output = context.Pe.ToBytes();
        PeImage reloaded = PeImage.Load(output);
        Assert.True(reloaded.DllChars.HasFlag(DllCharacteristics.DynamicBase));
        Assert.True(reloaded.DllChars.HasFlag(DllCharacteristics.HighEntropyVa));
        Assert.True(reloaded.DllChars.HasFlag(DllCharacteristics.NxCompatible));

        string[] imports = ImportTable.Parse(reloaded).Select(imported => imported.Name).ToArray();
        Assert.Contains("SetProcessMitigationPolicy", imports);
        Assert.Contains("ConvertStringSecurityDescriptorToSecurityDescriptorW", imports);
        Assert.Contains("SetSecurityInfo", imports);
        Assert.Contains("OutputDebugStringA", imports);
        Assert.Contains("ExitProcess", imports);

        AssertExtendedCharacteristics(reloaded, ExtendedDllCharacteristicsEditor.CetCompatible);

        PeImage.Section stub = Assert.Single(reloaded.Sections, section => section.Name == ".rmpt");
        PeImage.Section data = Assert.Single(reloaded.Sections, section => section.Name == ".rmpd");
        Assert.True(Contains(data.Data, Encoding.ASCII.GetBytes("RMPSTATE")));
        Assert.True(Contains(stub.Data, Encoding.ASCII.GetBytes("RMPBRND1")));
        Assert.True(Contains(stub.Data, Encoding.ASCII.GetBytes("RMPMSG01")));
        Assert.True(Contains(stub.Data, Encoding.UTF8.GetBytes("Example App owner 42")));
        Assert.True(Contains(stub.Data, Encoding.UTF8.GetBytes("Example App integrity warning")));
        Assert.True(Contains(stub.Data, Encoding.Unicode.GetBytes(
            "D:P(A;;GA;;;SY)(D;;0x22;;;WD)(A;;0x1FFFDD;;;WD)")));
        Assert.True(Contains(stub.Data, new byte[] { 0xF0, 0x49, 0x31, 0x45, 0x20 }),
            "The response consumer must update the shared session key atomically.");

        DataDirectory tls = reloaded.Directory(DataDir.Tls);
        Assert.False(tls.IsEmpty);
        ulong callbacksVa = BinaryPrimitives.ReadUInt64LittleEndian(reloaded.ReadRva(tls.RelativeVirtualAddress + 24, 8));
        uint callbacksRva = reloaded.VaToRva(callbacksVa);
        ulong firstCallbackVa = reloaded.ReadU64(callbacksRva);
        uint firstCallbackRva = reloaded.VaToRva(firstCallbackVa);
        Assert.True(stub.ContainsRva(firstCallbackRva));

        Assert.Contains(context.Log, entry => entry.Pass == "anti-inject.cet-shadow-stack");
        Assert.Contains(context.Log, entry => entry.Pass == "runtime-hardening");
    }

    [Fact]
    public void FullyHardenedFixturePreservesNativeExitCodeOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        ProtectionSettings settings = CreateSettings();
        byte[] protectedImage = new Protector().Protect(
            TestPeBuilder.Build(ctx =>
            {
                ctx.Code.MovRi(Reg.Rax, 12);
                ctx.Code.AddRi(Reg.Rax, 28);
            }),
            settings).Output;

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-runtime-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "hardened.exe");
        try
        {
            File.WriteAllBytes(executable, protectedImage);
            using Process? process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Hardened fixture did not exit within ten seconds.");
            Assert.Equal(40, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void EveryRuntimeKnobProducesDistinctInspectableOutput()
    {
        byte[] baseline = ProtectWith();
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);

        foreach (string knob in RuntimeKnobs)
        {
            (byte[] output, List<BuildLogEntry> log) = ProtectWithLog(knob);
            Assert.NotEqual(baseline, output);
            Assert.Contains(log, entry => entry.Pass == knob);
            Assert.True(fingerprints.Add(Convert.ToHexString(SHA256.HashData(output))),
                $"{knob} did not produce a distinct image.");
        }
    }

    [Fact]
    public void DaclHardeningDeniesNewVmWriteHandlesOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        ProtectionSettings settings = CreateSettings("anti-inject.dacl-hardening");
        byte[] input = TestPeBuilder.Build(ctx => ctx.Code.JmpShortSelf());
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();
        var pass = new RuntimeHardeningPass();
        pass.RunBeforeEntryPoint(context);
        new EntryPointPass().Run(context);
        pass.RunAfterEntryPoint(context);
        RelocBuilder.Rebuild(context);

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-dacl-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "dacl.exe");
        Process? process = null;
        try
        {
            File.WriteAllBytes(executable, context.Pe.ToBytes());
            process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);

            bool denied = false;
            for (int attempt = 0; attempt < 40 && !process.HasExited; attempt++)
            {
                IntPtr handle = OpenProcess(0x0020, false, process.Id); // PROCESS_VM_WRITE
                if (handle == IntPtr.Zero)
                {
                    denied = true;
                    break;
                }
                CloseHandle(handle);
                Thread.Sleep(25);
            }
            Assert.True(denied, "The hardened process still granted a new PROCESS_VM_WRITE handle.");

            IntPtr queryHandle = OpenProcess(0x1000, false, process.Id); // PROCESS_QUERY_LIMITED_INFORMATION
            Assert.NotEqual(IntPtr.Zero, queryHandle);
            CloseHandle(queryHandle);
        }
        finally
        {
            if (process is { HasExited: false })
                process.Kill(entireProcessTree: true);
            process?.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ToolResponseConsumesDetectionRaisedByAnotherEmitterOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        ProtectionSettings settings = CreateSettings("response.tool-response", "response.silent-taint");
        BuildContext context = BuildContext(settings);
        var pass = new RuntimeHardeningPass();
        pass.RunBeforeEntryPoint(context);

        // Model a producer such as AntiDebugPass setting the shared bit before
        // the response consumer runs. The monitor must observe rather than own
        // the detection source.
        RuntimeDetectionStateLayout state = RuntimeDetectionState.Ensure(context);
        context.WriteData(
            state.Rva + RuntimeDetectionStateLayout.DetectionFlagsOffset,
            BitConverter.GetBytes((ulong)RuntimeDetectionKind.DebuggerObserved));

        new EntryPointPass().Run(context);
        pass.RunAfterEntryPoint(context);
        RelocBuilder.Rebuild(context);

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-response-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string executable = Path.Combine(directory, "response.exe");
        try
        {
            File.WriteAllBytes(executable, context.Pe.ToBytes());
            using Process? process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Response fixture did not exit within ten seconds.");
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static ProtectionSettings CreateSettings(params string[] knobs)
    {
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Seed = 0x1234_5678;
        settings.Watermark = "Example App owner 42";
        settings.CustomMessage = "Example App integrity warning";
        foreach (string knob in knobs.Length == 0 ? RuntimeKnobs : knobs)
            settings.Knobs[knob] = ProtectionLevel.Light;
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        return settings;
    }

    private static byte[] ProtectWith(params string[] knobs) => ProtectWithLog(knobs).Output;

    private static (byte[] Output, List<BuildLogEntry> Log) ProtectWithLog(params string[] knobs)
    {
        BuildContext context = BuildContext(CreateSettings(knobs));
        var pass = new RuntimeHardeningPass();
        pass.RunBeforeEntryPoint(context);
        new EntryPointPass().Run(context);
        pass.RunAfterEntryPoint(context);
        RelocBuilder.Rebuild(context);
        return (context.Pe.ToBytes(), context.Log);
    }

    private static BuildContext BuildContext(ProtectionSettings settings)
    {
        byte[] input = TestPeBuilder.Build(ctx =>
        {
            ctx.Code.MovRi(Reg.Rax, 12);
            ctx.Code.AddRi(Reg.Rax, 28);
        });
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();
        return context;
    }

    private static void AssertExtendedCharacteristics(PeImage pe, ushort expected)
    {
        DataDirectory debug = pe.Directory(DataDir.Debug);
        Assert.False(debug.IsEmpty);
        int count = checked((int)(debug.Size / 28));
        for (int i = 0; i < count; i++)
        {
            byte[] descriptor = pe.ReadRva(debug.RelativeVirtualAddress + (uint)(i * 28), 28);
            if (BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12))
                != ExtendedDllCharacteristicsEditor.ImageDebugTypeExtendedDllCharacteristics)
                continue;
            uint payloadRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(20));
            ushort actual = BinaryPrimitives.ReadUInt16LittleEndian(pe.ReadRva(payloadRva, 2));
            Assert.Equal(expected, (ushort)(actual & expected));
            return;
        }
        Assert.Fail("Extended DLL characteristics debug record was not emitted.");
    }

    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) =>
        haystack.IndexOf(needle) >= 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
