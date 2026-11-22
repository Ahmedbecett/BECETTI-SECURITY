using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// ViewModel for the EDR & Hardening Command Center covering:
/// 1. Deep Persistence Hunter (Autoruns Pro)
/// 2. Hosts File & DNS Hijack Guard
/// 3. Camera & Microphone Access Auditor
/// 4. PowerShell & LOLBins Script Auditor + Base64 Decoder
/// 5. Phishing & Homograph URL Inspector
/// 6. Forensic Incident Evidence Bundle Exporter (.zip)
/// 7. File Integrity Monitor (FIM)
/// 8. Windows Hardening & Attack Surface Auditor
/// </summary>
public sealed class EdrCenterViewModel : ViewModelBase
{
    private readonly IPersistenceHunterService _persistence;
    private readonly IHostsDnsGuardService _hosts;
    private readonly ICameraMicAuditorService _cameraMic;
    private readonly IScriptCommandAuditorService _scripts;
    private readonly IUrlPhishingInspectorService _urlInspector;
    private readonly IIncidentEvidenceService _evidence;
    private readonly IFileIntegrityMonitorService _fim;
    private readonly IWindowsHardeningService _hardening;
    private readonly ISettingsService _settings;
    private readonly IEventLogService _events;

    private bool _hostsGuardWatching;
    private bool _fimWatching;
    private string _persistenceSummary = "Click 'Audit Persistence' to inspect Scheduled Tasks, Services, Winlogon, IFEO, and AppInit_DLLs.";
    private string _hostsSummary = "Click 'Audit Hosts & DNS' to verify system hosts file and DNS resolvers.";
    private string _cameraMicSummary = "Click 'Audit Camera & Mic' to inspect live and recent hardware access.";
    private string _scriptSummary = "Click 'Audit Scripts & LOLBins' to scan live process command lines and PowerShell 4104 logs.";
    private string _base64Input = string.Empty;
    private string _decodedBase64Output = string.Empty;
    private string _urlToInspect = string.Empty;
    private string _urlReportSummary = "Paste any URL to check for Punycode/Homograph spoofing, redirect chains, and TLS validity.";
    private string _fimSummary = "Add sensitive files to monitor their SHA-256 cryptographic integrity.";
    private string _hardeningScoreText = "—";
    private string _hardeningSummary = "Click 'Audit Windows Hardening' to verify UAC, Secure Boot, HVCI, SMBv1, RDP, TPM, and BitLocker.";
    private bool _createRestorePointBeforeFix;
    private string _evidenceSummary = "Export a timestamped ZIP bundle with live processes, network, YARA, persistence, hardening, and SHA-256 hash.";

    public EdrCenterViewModel(
        IPersistenceHunterService persistence,
        IHostsDnsGuardService hosts,
        ICameraMicAuditorService cameraMic,
        IScriptCommandAuditorService scripts,
        IUrlPhishingInspectorService urlInspector,
        IIncidentEvidenceService evidence,
        IFileIntegrityMonitorService fim,
        IWindowsHardeningService hardening,
        ISettingsService settings,
        IEventLogService events)
    {
        _persistence = persistence;
        _hosts = hosts;
        _cameraMic = cameraMic;
        _scripts = scripts;
        _urlInspector = urlInspector;
        _evidence = evidence;
        _fim = fim;
        _hardening = hardening;
        _settings = settings;
        _events = events;

        LoadCommand = new RelayCommand(LoadAsync);
        AuditPersistenceCommand = new RelayCommand(AuditPersistenceAsync);
        AuditHostsDnsCommand = new RelayCommand(AuditHostsDnsAsync);
        ApplyCloudflareDnsCommand = new RelayCommand(() => ApplyDnsAsync(DnsProtectionPreset.CloudflareMalware));
        ApplyQuad9DnsCommand = new RelayCommand(() => ApplyDnsAsync(DnsProtectionPreset.Quad9Secure));
        RestoreDhcpDnsCommand = new RelayCommand(() => ApplyDnsAsync(DnsProtectionPreset.AutomaticDhcp));
        AuditCameraMicCommand = new RelayCommand(AuditCameraMicAsync);
        AuditScriptsCommand = new RelayCommand(AuditScriptsAsync);
        DecodeBase64Command = new RelayCommand(() => { DecodeBase64(); return Task.CompletedTask; });
        InspectUrlCommand = new RelayCommand(InspectUrlAsync, () => !string.IsNullOrWhiteSpace(UrlToInspect));
        VerifyFimCommand = new RelayCommand(VerifyFimAsync);
        AuditHardeningCommand = new RelayCommand(AuditHardeningAsync);
        ExportEvidenceCommand = new RelayCommand(ExportEvidenceAsync);
    }

    public ObservableCollection<PersistenceEntry> PersistenceEntries { get; } = new();
    public ObservableCollection<HostsMappingEntry> HostsMappings { get; } = new();
    public ObservableCollection<AdapterDnsInfo> AdapterDnsList { get; } = new();
    public ObservableCollection<DevicePrivacyAccessEntry> CameraMicEntries { get; } = new();
    public ObservableCollection<SuspiciousScriptEvent> ScriptFindings { get; } = new();
    public ObservableCollection<string> UrlFindings { get; } = new();
    public ObservableCollection<FimCheckItem> FimItems { get; } = new();
    public ObservableCollection<HardeningCheckItem> HardeningChecks { get; } = new();

    public RelayCommand LoadCommand { get; }
    public RelayCommand AuditPersistenceCommand { get; }
    public RelayCommand AuditHostsDnsCommand { get; }
    public RelayCommand ApplyCloudflareDnsCommand { get; }
    public RelayCommand ApplyQuad9DnsCommand { get; }
    public RelayCommand RestoreDhcpDnsCommand { get; }
    public RelayCommand AuditCameraMicCommand { get; }
    public RelayCommand AuditScriptsCommand { get; }
    public RelayCommand DecodeBase64Command { get; }
    public RelayCommand InspectUrlCommand { get; }
    public RelayCommand VerifyFimCommand { get; }
    public RelayCommand AuditHardeningCommand { get; }
    public RelayCommand ExportEvidenceCommand { get; }

    public bool HostsGuardWatching
    {
        get => _hostsGuardWatching;
        set
        {
            if (SetProperty(ref _hostsGuardWatching, value))
                _ = ToggleHostsGuardAsync(value);
        }
    }

    public bool FimWatching
    {
        get => _fimWatching;
        set
        {
            if (SetProperty(ref _fimWatching, value))
                _ = ToggleFimWatchAsync(value);
        }
    }

    public string PersistenceSummary { get => _persistenceSummary; set => SetProperty(ref _persistenceSummary, value); }
    public string HostsSummary { get => _hostsSummary; set => SetProperty(ref _hostsSummary, value); }
    public string CameraMicSummary { get => _cameraMicSummary; set => SetProperty(ref _cameraMicSummary, value); }
    public string ScriptSummary { get => _scriptSummary; set => SetProperty(ref _scriptSummary, value); }
    public string Base64Input { get => _base64Input; set => SetProperty(ref _base64Input, value); }
    public string DecodedBase64Output { get => _decodedBase64Output; set => SetProperty(ref _decodedBase64Output, value); }

    public string UrlToInspect
    {
        get => _urlToInspect;
        set
        {
            if (SetProperty(ref _urlToInspect, value))
                InspectUrlCommand.RaiseCanExecuteChanged();
        }
    }

    public string UrlReportSummary { get => _urlReportSummary; set => SetProperty(ref _urlReportSummary, value); }
    public string FimSummary { get => _fimSummary; set => SetProperty(ref _fimSummary, value); }
    public string HardeningScoreText { get => _hardeningScoreText; set => SetProperty(ref _hardeningScoreText, value); }
    public string HardeningSummary { get => _hardeningSummary; set => SetProperty(ref _hardeningSummary, value); }
    public string EvidenceSummary { get => _evidenceSummary; set => SetProperty(ref _evidenceSummary, value); }

    public async Task LoadAsync()
    {
        _hostsGuardWatching = _hosts.IsWatching;
        OnPropertyChanged(nameof(HostsGuardWatching));
        _fimWatching = _fim.IsWatching;
        OnPropertyChanged(nameof(FimWatching));

        await VerifyFimAsync();
        await AuditHardeningAsync();
    }

    public async Task AuditPersistenceAsync()
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _persistence.AuditAsync();
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            PersistenceEntries.Clear();
            foreach (var e in res.Value.Entries)
                PersistenceEntries.Add(e);

            PersistenceSummary = res.Message;
            StatusMessage = res.Message;
            await _events.RecordAsync("edr.persistence.audit", res.Message, true);
        }
        finally { IsBusy = false; }
    }

    public async Task DisableTaskAsync(PersistenceEntry entry)
    {
        if (!entry.CanDisable) return;
        ClearMessages();
        var res = await _persistence.DisableScheduledTaskAsync(entry.Name);
        if (res.Success)
        {
            StatusMessage = res.Message;
            await _events.RecordAsync("edr.persistence.disabled", res.Message, true, entry.Name);
            await AuditPersistenceAsync();
        }
        else
        {
            ErrorMessage = res.Message;
        }
    }

    public async Task AuditHostsDnsAsync()
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _hosts.AuditAsync();
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            HostsMappings.Clear();
            foreach (var m in res.Value.Mappings)
                HostsMappings.Add(m);

            AdapterDnsList.Clear();
            foreach (var a in res.Value.Adapters)
                AdapterDnsList.Add(a);

            HostsSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    private async Task ToggleHostsGuardAsync(bool enable)
    {
        var res = enable ? _hosts.StartWatching() : _hosts.StopWatching();
        _settings.Current.HostsGuardEnabled = enable;
        await _settings.SaveAsync();
        if (res.Success) StatusMessage = res.Message;
        else ErrorMessage = res.Message;
    }

    private async Task ApplyDnsAsync(DnsProtectionPreset preset)
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _hosts.ApplyDnsProtectionAsync(preset);
            if (res.Success)
            {
                StatusMessage = res.Message;
                await _events.RecordAsync("edr.dns.changed", res.Message, true);
                await AuditHostsDnsAsync();
            }
            else
            {
                ErrorMessage = res.Message;
            }
        }
        finally { IsBusy = false; }
    }

    public async Task AuditCameraMicAsync()
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _cameraMic.AuditAsync();
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            CameraMicEntries.Clear();
            foreach (var e in res.Value.Entries)
                CameraMicEntries.Add(e);

            CameraMicSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task AuditScriptsAsync()
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _scripts.AuditAsync();
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            ScriptFindings.Clear();
            foreach (var f in res.Value.Findings)
                ScriptFindings.Add(f);

            ScriptSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public void DecodeBase64()
    {
        if (string.IsNullOrWhiteSpace(Base64Input))
        {
            DecodedBase64Output = string.Empty;
            return;
        }
        var decoded = _scripts.TryDecodePowerShellBase64(Base64Input);
        DecodedBase64Output = decoded ?? "Could not decode valid UTF-16LE or UTF-8 Base64 text from input.";
    }

    public async Task InspectUrlAsync()
    {
        if (string.IsNullOrWhiteSpace(UrlToInspect)) return;
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _urlInspector.InspectUrlAsync(UrlToInspect.Trim(), performLiveNetworkCheck: true);
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            var r = res.Value;
            UrlFindings.Clear();
            foreach (var f in r.Findings)
                UrlFindings.Add(f);
            if (r.TlsInspected)
                UrlFindings.Add($"TLS Certificate: {(r.TlsValid ? "Valid" : "INVALID")} · Issuer: {r.TlsIssuer} · Expires in {r.TlsDaysRemaining} day(s)");
            if (r.RedirectChain.Count > 1)
                UrlFindings.Add($"Redirect chain ({r.RedirectChain.Count} hops): {string.Join(" -> ", r.RedirectChain)}");

            UrlReportSummary = $"Risk: {r.RiskLevel} ({r.RiskScore}/100) · Punycode: {r.PunycodeHost} · HTTPS: {(r.UsesHttps ? "Yes" : "No")}";
            StatusMessage = res.Message;
            await _events.RecordAsync("edr.url.inspected", UrlReportSummary, true, r.OriginalUrl);
        }
        finally { IsBusy = false; }
    }

    public async Task AddFimFileAsync(string path)
    {
        ClearMessages();
        var res = await _fim.TrackFileAsync(path);
        if (res.Success)
        {
            StatusMessage = res.Message;
            await VerifyFimAsync();
        }
        else
        {
            ErrorMessage = res.Message;
        }
    }

    public async Task UntrackFimFileAsync(string path)
    {
        ClearMessages();
        var res = await _fim.UntrackFileAsync(path);
        if (res.Success)
        {
            StatusMessage = res.Message;
            await VerifyFimAsync();
        }
        else
        {
            ErrorMessage = res.Message;
        }
    }

    public async Task RebaselineFimFileAsync(string path)
    {
        ClearMessages();
        var res = await _fim.RebaselineFileAsync(path);
        if (res.Success)
        {
            StatusMessage = res.Message;
            await VerifyFimAsync();
        }
        else
        {
            ErrorMessage = res.Message;
        }
    }

    public async Task VerifyFimAsync()
    {
        var res = await _fim.VerifyAllAsync();
        if (!res.Success || res.Value is null) return;

        FimItems.Clear();
        foreach (var item in res.Value.Items)
            FimItems.Add(item);

        FimSummary = res.Value.TotalTracked == 0
            ? "No files tracked yet. Click 'Track Sensitive File' to record a SHA-256 baseline."
            : res.Message;
    }

    private async Task ToggleFimWatchAsync(bool enable)
    {
        var res = enable ? await _fim.StartWatchingAsync() : _fim.StopWatching();
        _settings.Current.FimAutoWatchEnabled = enable;
        await _settings.SaveAsync();
        if (res.Success) StatusMessage = res.Message;
        else ErrorMessage = res.Message;
    }

    public async Task AuditHardeningAsync()
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _hardening.AuditAsync();
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            HardeningChecks.Clear();
            foreach (var c in res.Value.Checks)
                HardeningChecks.Add(c);

            HardeningScoreText = $"{res.Value.ScorePercent}%";
            HardeningSummary = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task ExportEvidenceAsync()
    {
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _evidence.ExportForensicBundleAsync();
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            EvidenceSummary = $"Saved: {res.Value.BundleZipPath}\nSHA-256: {res.Value.Sha256}\nArtifacts: {string.Join(", ", res.Value.IncludedArtifacts)}";
            StatusMessage = res.Message;
            await _events.RecordAsync("edr.evidence.exported", res.Message, true, res.Value.BundleZipPath);
        }
        finally { IsBusy = false; }
    }

    public bool CreateRestorePointBeforeFix
    {
        get => _createRestorePointBeforeFix;
        set => SetProperty(ref _createRestorePointBeforeFix, value);
    }

    public async Task RemediateHardeningCheckAsync(HardeningCheckItem check)
    {
        if (check is null || !check.CanAutoFix) return;
        ClearMessages();
        IsBusy = true;
        try
        {
            var res = await _hardening.RemediateCheckAsync(check.Id, CreateRestorePointBeforeFix);
            if (!res.Success)
            {
                ErrorMessage = res.Message;
                return;
            }

            StatusMessage = res.Message;
            await _events.RecordAsync("edr.hardening.remediated", res.Message, true, check.Id);
            await AuditHardeningAsync();
        }
        finally { IsBusy = false; }
    }

    public string BuildPersistenceAiPrompt(PersistenceEntry entry) =>
        $"Analyze this Windows persistence entry detected by BECETTI SECURITY Deep Persistence Hunter:\n" +
        $"Category: {entry.Category}\nName: {entry.Name}\nLocation: {entry.SourceLocation}\n" +
        $"Command: {entry.Command}\nSignature: {entry.SignatureStatus} ({entry.Publisher})\n" +
        $"Risk: {entry.RiskLevel} — {entry.RiskReason}\n" +
        $"Tell me if this looks legitimate or suspicious, and exact safe steps to verify or remove it.";

    public string BuildUrlAiPrompt() =>
        $"Analyze this URL inspection from BECETTI SECURITY Phishing & Homograph Inspector:\n" +
        $"URL: {UrlToInspect}\nSummary: {UrlReportSummary}\nFindings:\n- {string.Join("\n- ", UrlFindings)}\n" +
        $"Should I trust this link or block it? Explain concisely.";

    public string BuildScriptAiPrompt(string scriptOrDecoded) =>
        $"Analyze this Windows PowerShell / LOLBin command captured by BECETTI SECURITY EDR Auditor. Explain whether it is benign or malicious, what each flag does, and safe remediation steps:\n\n{scriptOrDecoded}";
}
