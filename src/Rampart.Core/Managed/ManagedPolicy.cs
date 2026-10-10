using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Rampart.Config;

namespace Rampart.Managed;

internal static class ManagedPolicy
{
    internal static ManagedMethodIdentity Identity(MethodDefinition method)
    {
        var assembly = method.Module.Assembly.Name.FullName;
        var signature = method.FullName;
        var canonical = assembly + "|" + method.Module.Name + "|" + signature;
        return new ManagedMethodIdentity(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))), assembly,
            method.Module.Name, method.DeclaringType.Namespace, method.DeclaringType.FullName, method.Name, signature,
            method.MetadataToken.ToInt32(), method.DebugInformation.SequencePoints.FirstOrDefault()?.Document.Url,
            method.CustomAttributes.Any(a => a.AttributeType.Name == "CompilerGeneratedAttribute")
            || method.DeclaringType.CustomAttributes.Any(a => a.AttributeType.Name == "CompilerGeneratedAttribute"));
    }

    internal sealed record Selection(bool Included, bool Vm, bool Strings, bool Constants, bool ControlFlow, bool Rename);

    internal static Selection Select(ManagedMethodIdentity identity, ManagedProtectionOptions options, int[] counts)
    {
        var included = true;
        var vm = false;
        var strings = options.Strings; var constants = options.Constants;
        var controlFlow = options.ControlFlow; var rename = options.RenamePrivateMembers;
        for (var i = 0; i < options.Rules.Count; i++)
        {
            var rule = options.Rules[i];
            if (!Matches(rule.Assembly, identity.Assembly) || !Matches(rule.Module, identity.Module)
                || !Matches(rule.Namespace, identity.Namespace) || !Matches(rule.Type, identity.Type)
                || !(Matches(rule.Method, identity.Method) || Matches(rule.Method, identity.Signature)) || !Matches(rule.Signature, identity.Signature)
                || !Matches(rule.SourceDocument, identity.SourceDocument ?? "")
                || rule.MetadataToken is { } token && token != identity.MetadataToken
                || rule.GeneratedCode is { } generated && generated != identity.GeneratedCode) continue;
            counts[i]++;
            included = rule.Include ?? included;
            vm = rule.Virtualize ?? vm;
            strings = rule.Strings ?? strings; constants = rule.Constants ?? constants;
            controlFlow = rule.ControlFlow ?? controlFlow; rename = rule.RenamePrivateMembers ?? rename;
        }
        return new Selection(included, vm, strings, constants, controlFlow, rename);
    }

    // Iterative glob matching avoids regex backtracking and mirrors the native * / ? grammar.
    internal static bool Matches(string pattern, string value)
    {
        var p = 0; var v = 0; var star = -1; var retry = 0;
        while (v < value.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(value[v]))) { p++; v++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; retry = v; }
            else if (star >= 0) { p = star + 1; v = ++retry; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
