using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface ISigmaRuleScannerService
{
    IReadOnlyList<SigmaRuleDefinition> GetLoadedRules();
    Task<OperationResult<SigmaRuleDefinition>> ImportYamlRuleAsync(string yamlFilePath, CancellationToken ct = default);
    Task<OperationResult<SigmaScanReport>> ScanWindowsEventsAsync(CancellationToken ct = default);
}

/// <summary>
/// #9: Local Sigma Rule Scanner (YAML Detection Rules over Real Windows Event Logs).
/// Ships with 8 built-in MITRE ATT&amp;CK Enterprise Sigma rules + imports custom .yml/.yaml
/// Sigma rules from disk, evaluating them directly against real Windows Event Logs collected
/// by ILocalSiemService. Zero simulation.
/// </summary>
public sealed class SigmaRuleScannerService : ISigmaRuleScannerService
{
    private readonly ILocalSiemService _siem;
    private readonly string _customRulesDir;
    private readonly List<SigmaRuleDefinition> _customRules = new();
    private readonly object _lock = new();

    private static readonly IReadOnlyList<SigmaRuleDefinition> BuiltInRules = new[]
    {
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-001", Title = "PowerShell EncodedCommand or Download Cradle", Level = "high",
            LogSource = "powershell", MitreTechniqueId = "T1059.001",
            EventIds = new[] { 4104, 4688 },
            KeywordsAny = new[] { "-encodedcommand", "-enc ", "frombase64string", "downloadstring", "invoke-expression" }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-002", Title = "Shadow Copy Deletion / Recovery Inhibition", Level = "critical",
            LogSource = "windows", MitreTechniqueId = "T1490",
            KeywordsAny = new[] { "vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set", "wbadmin delete catalog" }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-003", Title = "Windows Security or System Event Log Cleared", Level = "critical",
            LogSource = "security", MitreTechniqueId = "T1070.001",
            EventIds = new[] { 1102, 104 }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-004", Title = "Microsoft Defender Real-Time Protection Tampering or Detection", Level = "critical",
            LogSource = "defender", MitreTechniqueId = "T1562.001",
            EventIds = new[] { 1116, 1117, 5001, 5007 },
            KeywordsAny = new[] { "disablerealtimemonitoring", "add-mppreference", "threat", "malware" }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-005", Title = "Suspicious New Windows Service Created (Event 7045)", Level = "high",
            LogSource = "system", MitreTechniqueId = "T1543.003",
            EventIds = new[] { 7045 },
            KeywordsAny = new[] { "powershell", "cmd.exe", "temp\\", "appdata\\", "mshta", "rundll32" }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-006", Title = "AMSI / ETW Memory Patching Attempt", Level = "critical",
            LogSource = "powershell", MitreTechniqueId = "T1562.001",
            KeywordsAny = new[] { "amsiinitfailed", "amsiscanbuffer", "etweventwrite" }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-007", Title = "Certutil / Bitsadmin Ingress Tool Transfer", Level = "high",
            LogSource = "windows", MitreTechniqueId = "T1105",
            KeywordsAny = new[] { "certutil -urlcache", "certutil.exe -urlcache", "bitsadmin /transfer" }
        },
        new SigmaRuleDefinition
        {
            Id = "sigma-becetti-008", Title = "LSASS / Credential Access Indicator", Level = "critical",
            LogSource = "windows", MitreTechniqueId = "T1003.001",
            KeywordsAny = new[] { "sekurlsa::", "comsvcs.dll", "minidump", "reg save hklm\\sam" }
        }
    };

    public SigmaRuleScannerService(ILocalSiemService siem, ISettingsService settings)
    {
        _siem = siem;
        _customRulesDir = Path.Combine(settings.DataDirectory, "sigma-rules");
        Directory.CreateDirectory(_customRulesDir);
        LoadPersistedCustomRules();
    }

    public IReadOnlyList<SigmaRuleDefinition> GetLoadedRules()
    {
        lock (_lock)
            return BuiltInRules.Concat(_customRules).ToList();
    }

    public async Task<OperationResult<SigmaRuleDefinition>> ImportYamlRuleAsync(string yamlFilePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(yamlFilePath) || !File.Exists(yamlFilePath))
            return OperationResult<SigmaRuleDefinition>.Fail("Select a valid Sigma .yml or .yaml file.");

        var yaml = await File.ReadAllTextAsync(yamlFilePath, ct).ConfigureAwait(false);
        var parsed = ParseSigmaYaml(yaml, Path.GetFileName(yamlFilePath));
        if (parsed is null)
            return OperationResult<SigmaRuleDefinition>.Fail("Invalid Sigma YAML: must contain a 'title:' and at least one detection keyword or EventID.");

        var dest = Path.Combine(_customRulesDir, Path.GetFileName(yamlFilePath));
        await File.WriteAllTextAsync(dest, yaml, ct).ConfigureAwait(false);

        lock (_lock)
        {
            _customRules.RemoveAll(r => r.SourceFile.Equals(parsed.SourceFile, StringComparison.OrdinalIgnoreCase));
            _customRules.Add(parsed);
        }

        return OperationResult<SigmaRuleDefinition>.Ok(parsed, $"Imported Sigma rule '{parsed.Title}' ({parsed.Level}).");
    }

    public async Task<OperationResult<SigmaScanReport>> ScanWindowsEventsAsync(CancellationToken ct = default)
    {
        var siemRes = await _siem.CollectAndCorrelateAsync(50, ct).ConfigureAwait(false);
        if (!siemRes.Success || siemRes.Value is null)
            return OperationResult<SigmaScanReport>.Fail(siemRes.Message, siemRes.ErrorCode);

        var rules = GetLoadedRules();
        var matches = EvaluateRules(rules, siemRes.Value.RecentEvents);

        var summary = matches.Count > 0
            ? $"Sigma Alert: {matches.Count} rule match(es) across {siemRes.Value.RecentEvents.Count} live Windows events ({rules.Count} rules)."
            : $"Sigma Clean: {rules.Count} Sigma rules evaluated against {siemRes.Value.RecentEvents.Count} live Windows events, 0 matches.";

        return OperationResult<SigmaScanReport>.Ok(new SigmaScanReport
        {
            ScannedAt = DateTimeOffset.UtcNow,
            RulesEvaluated = rules.Count,
            EventsEvaluated = siemRes.Value.RecentEvents.Count,
            Matches = matches,
            Summary = summary
        }, summary);
    }

    internal static IReadOnlyList<SigmaRuleMatch> EvaluateRules(
        IReadOnlyList<SigmaRuleDefinition> rules,
        IReadOnlyList<SiemEventEntry> events)
    {
        var matches = new List<SigmaRuleMatch>();

        foreach (var rule in rules)
        {
            foreach (var ev in events)
            {
                if (!MatchesRule(rule, ev)) continue;
                matches.Add(new SigmaRuleMatch
                {
                    RuleTitle = rule.Title,
                    Level = rule.Level,
                    MitreTechniqueId = string.IsNullOrWhiteSpace(rule.MitreTechniqueId) ? ev.MitreTechniqueId : rule.MitreTechniqueId,
                    EventId = ev.EventId,
                    LogName = ev.LogName,
                    Timestamp = ev.Timestamp,
                    MatchedExcerpt = ev.Message.Length > 180 ? ev.Message[..180] + "…" : ev.Message
                });
            }
        }

        return matches.OrderByDescending(m => m.Timestamp).Take(100).ToList();
    }

    private static bool MatchesRule(SigmaRuleDefinition rule, SiemEventEntry ev)
    {
        if (rule.EventIds.Count > 0 && !rule.EventIds.Contains(ev.EventId))
            return false;

        var corpus = $"{ev.LogName} {ev.ProviderName} {ev.Message}".ToLowerInvariant();

        if (rule.KeywordsAll.Count > 0 && !rule.KeywordsAll.All(k => corpus.Contains(k.ToLowerInvariant())))
            return false;

        if (rule.KeywordsAny.Count > 0 && !rule.KeywordsAny.Any(k => corpus.Contains(k.ToLowerInvariant())))
            return false;

        return rule.EventIds.Count > 0 || rule.KeywordsAny.Count > 0 || rule.KeywordsAll.Count > 0;
    }

    internal static SigmaRuleDefinition? ParseSigmaYaml(string yaml, string sourceFile)
    {
        if (string.IsNullOrWhiteSpace(yaml)) return null;

        string title = string.Empty, id = Guid.NewGuid().ToString("N")[..10], level = "medium", mitre = "T1059";
        var keywords = new List<string>();
        var eventIds = new List<int>();
        bool inDetection = false;

        foreach (var raw in yaml.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = raw.Trim();
            if (trimmed.StartsWith('#')) continue;

            if (trimmed.StartsWith("title:", StringComparison.OrdinalIgnoreCase))
                title = trimmed[6..].Trim().Trim('\'', '"');
            else if (trimmed.StartsWith("id:", StringComparison.OrdinalIgnoreCase))
                id = trimmed[3..].Trim().Trim('\'', '"');
            else if (trimmed.StartsWith("level:", StringComparison.OrdinalIgnoreCase))
                level = trimmed[6..].Trim().Trim('\'', '"');
            else if (trimmed.Contains("attack.t", StringComparison.OrdinalIgnoreCase))
            {
                var m = Regex.Match(trimmed, "attack\\.(t\\d{4}(?:\\.\\d{3})?)", RegexOptions.IgnoreCase);
                if (m.Success) mitre = m.Groups[1].Value.ToUpperInvariant();
            }
            else if (trimmed.StartsWith("detection:", StringComparison.OrdinalIgnoreCase))
                inDetection = true;
            else if (inDetection)
            {
                if (trimmed.StartsWith("EventID:", StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(trimmed[8..].Trim().Trim('\'', '"'), out var eid))
                        eventIds.Add(eid);
                }
                else if (trimmed.StartsWith("- "))
                {
                    var val = trimmed[2..].Trim().Trim('\'', '"');
                    if (int.TryParse(val, out var eid)) eventIds.Add(eid);
                    else if (val.Length >= 3 && !val.StartsWith("attack.", StringComparison.OrdinalIgnoreCase))
                        keywords.Add(val);
                }
            }
        }

        if (string.IsNullOrWhiteSpace(title) || (keywords.Count == 0 && eventIds.Count == 0))
            return null;

        return new SigmaRuleDefinition
        {
            Id = id,
            Title = title,
            Level = level,
            LogSource = "custom-yaml",
            MitreTechniqueId = mitre,
            KeywordsAny = keywords,
            EventIds = eventIds,
            SourceFile = sourceFile
        };
    }

    private void LoadPersistedCustomRules()
    {
        try
        {
            foreach (var f in Directory.GetFiles(_customRulesDir, "*.y*ml"))
            {
                var parsed = ParseSigmaYaml(File.ReadAllText(f), Path.GetFileName(f));
                if (parsed is not null) _customRules.Add(parsed);
            }
        }
        catch { }
    }
}
