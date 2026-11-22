using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Maps real BECETTI SECURITY EDR, Persistence, Script/LOLBins, DLL Injection, Network,
/// Ransomware, Phishing, and Threat Feed detections to official MITRE ATT&amp;CK Enterprise
/// Technique IDs, Tactics, and official documentation URLs.
/// </summary>
public static class MitreAttackMapper
{
    private static readonly Dictionary<string, MitreAttackReference> Catalog = new(StringComparer.OrdinalIgnoreCase)
    {
        ["T1059.001"] = Ref("T1059.001", "PowerShell", "Execution"),
        ["T1059.003"] = Ref("T1059.003", "Windows Command Shell", "Execution"),
        ["T1218.005"] = Ref("T1218.005", "Mshta", "Defense Evasion"),
        ["T1218.010"] = Ref("T1218.010", "Regsvr32", "Defense Evasion"),
        ["T1218.011"] = Ref("T1218.011", "Rundll32", "Defense Evasion"),
        ["T1105"] = Ref("T1105", "Ingress Tool Transfer", "Command and Control"),
        ["T1197"] = Ref("T1197", "BITS Jobs", "Defense Evasion"),
        ["T1053.005"] = Ref("T1053.005", "Scheduled Task", "Persistence"),
        ["T1543.003"] = Ref("T1543.003", "Windows Service", "Persistence"),
        ["T1547.001"] = Ref("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
        ["T1547.004"] = Ref("T1547.004", "Winlogon Helper DLL", "Persistence"),
        ["T1546.010"] = Ref("T1546.010", "AppInit DLLs", "Persistence"),
        ["T1546.012"] = Ref("T1546.012", "Image File Execution Options Injection", "Persistence"),
        ["T1055.001"] = Ref("T1055.001", "Dynamic-link Library Injection", "Defense Evasion"),
        ["T1574.002"] = Ref("T1574.002", "DLL Side-Loading", "Defense Evasion"),
        ["T1565.001"] = Ref("T1565.001", "Stored Data Manipulation (Hosts File)", "Impact"),
        ["T1486"] = Ref("T1486", "Data Encrypted for Impact (Ransomware)", "Impact"),
        ["T1557.002"] = Ref("T1557.002", "ARP Cache Poisoning", "Credential Access"),
        ["T1566.002"] = Ref("T1566.002", "Spearphishing Link / IDN Homograph", "Initial Access"),
        ["T1176"] = Ref("T1176", "Browser Extensions", "Persistence"),
        ["T1071"] = Ref("T1071", "Application Layer Protocol (C2)", "Command and Control"),
        ["T1115"] = Ref("T1115", "Clipboard Data Hijacking", "Collection"),
        ["T1125"] = Ref("T1125", "Video / Audio Capture", "Collection"),
        ["T1204.002"] = Ref("T1204.002", "Malicious File Execution (YARA)", "Execution")
    };

    public static MitreAttackReference GetById(string techniqueId)
    {
        if (!string.IsNullOrWhiteSpace(techniqueId) && Catalog.TryGetValue(techniqueId.Trim(), out var item))
            return item;
        return Ref("T1204.002", "Malicious File Execution", "Execution");
    }

    public static IReadOnlyList<MitreAttackReference> GetAllMappedTechniques() =>
        Catalog.Values.OrderBy(v => v.TechniqueId, StringComparer.Ordinal).ToList();

    public static MitreAttackReference MapPersistenceCategory(string category) =>
        (category ?? string.Empty).ToLowerInvariant() switch
        {
            var c when c.Contains("scheduled") => GetById("T1053.005"),
            var c when c.Contains("service") => GetById("T1543.003"),
            var c when c.Contains("winlogon") => GetById("T1547.004"),
            var c when c.Contains("ifeo") => GetById("T1546.012"),
            var c when c.Contains("appinit") => GetById("T1546.010"),
            _ => GetById("T1547.001")
        };

    public static MitreAttackReference MapScriptCommand(string processOrCommand)
    {
        var lower = (processOrCommand ?? string.Empty).ToLowerInvariant();
        if (lower.Contains("mshta")) return GetById("T1218.005");
        if (lower.Contains("regsvr32")) return GetById("T1218.010");
        if (lower.Contains("rundll32")) return GetById("T1218.011");
        if (lower.Contains("bitsadmin")) return GetById("T1197");
        if (lower.Contains("certutil") || lower.Contains("downloadstring") || lower.Contains("invoke-webrequest")) return GetById("T1105");
        if (lower.Contains("powershell") || lower.Contains("pwsh") || lower.Contains("-enc")) return GetById("T1059.001");
        return GetById("T1059.003");
    }

    public static MitreAttackReference MapDllFinding(string riskReason)
    {
        var lower = (riskReason ?? string.Empty).ToLowerInvariant();
        return lower.Contains("temp") || lower.Contains("sideload") || lower.Contains("user-writable")
            ? GetById("T1574.002")
            : GetById("T1055.001");
    }

    private static MitreAttackReference Ref(string id, string name, string tactic)
    {
        var urlPath = id.Replace('.', '/');
        return new MitreAttackReference
        {
            TechniqueId = id,
            TechniqueName = name,
            Tactic = tactic,
            Url = $"https://attack.mitre.org/techniques/{urlPath}/"
        };
    }
}
