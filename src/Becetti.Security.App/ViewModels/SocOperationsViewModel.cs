using System.Collections.ObjectModel;
using System.Windows.Input;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Enterprise SOC Operations Hub ViewModel powering 6 real-time security modules:
/// #1 Local SIEM &amp; Event Correlation, #9 Sigma Rule Scanner, #8 Live Process Tree Hunter,
/// #4 SOAR Automated Response Playbooks, #7 EML Email Phishing Forensics, and #5 Root Cert Auditor.
/// </summary>
public sealed class SocOperationsViewModel : ViewModelBase
{
    private readonly ILocalSiemService _siem;
    private readonly ISigmaRuleScannerService _sigma;
    private readonly IProcessTreeHunterService _procTree;
    private readonly ISoarPlaybookService _soar;
    private readonly IEmailForensicsService _email;
    private readonly IRootCertAuditorService _rootCerts;
    private readonly IAiTriageNavigator _aiTriage;

    // #1 SIEM
    private string _siemSummary = "Click 'Collect & Correlate Events' to analyze live Windows Security, PowerShell, Defender & System logs.";
    // #9 Sigma
    private string _sigmaSummary = "8 built-in MITRE ATT&CK Sigma rules ready. Scan live Windows events or import custom .yml Sigma rules.";
    // #8 Process Tree
    private string _procTreeSummary = "Click 'Capture Live Process Tree' to inspect Parent->Child relationships, signatures & EDR anomalies.";
    private ProcessTreeNode? _selectedProcess;
    // #4 SOAR
    private bool _soarAutoKill;
    private bool _soarAutoFirewall;
    private bool _soarAutoQuarantine;
    private bool _soarGenerateEvidence;
    private string _soarTargetPidText = string.Empty;
    private string _soarTargetPath = string.Empty;
    private string _soarReason = "Manual SOC containment trigger";
    private string _soarSummary = "Configure automated response steps below and trigger containment on demand.";
    // #7 Email Forensics
    private string _emlInputText = string.Empty;
    private string _emlSummary = "Open an .eml file or paste raw RFC 5322 email headers/body to verify SPF/DKIM/DMARC & URLhaus links.";
    private string _emlMetaHeader = "—";
    // #5 Root Certs
    private string _rootCertSummary = "Click 'Audit Windows Root CAs' to detect suspicious user-installed HTTPS MITM certificates & weak algorithms.";

    public SocOperationsViewModel(
        ILocalSiemService siem,
        ISigmaRuleScannerService sigma,
        IProcessTreeHunterService procTree,
        ISoarPlaybookService soar,
        IEmailForensicsService email,
        IRootCertAuditorService rootCerts,
        IAiTriageNavigator aiTriage)
    {
        _siem = siem;
        _sigma = sigma;
        _procTree = procTree;
        _soar = soar;
        _email = email;
        _rootCerts = rootCerts;
        _aiTriage = aiTriage;

        LoadSoarConfig();
        RefreshSigmaRulesList();

        RunSiemCommand = new RelayCommand(RunSiemAsync);
        RunSigmaScanCommand = new RelayCommand(RunSigmaScanAsync);
        CaptureProcessTreeCommand = new RelayCommand(CaptureProcessTreeAsync);
        KillSelectedProcessCommand = new RelayCommand(() => { KillSelectedProcess(); return Task.CompletedTask; });
        SaveSoarConfigCommand = new RelayCommand(SaveSoarConfigAsync);
        ExecuteSoarCommand = new RelayCommand(ExecuteSoarAsync);
        AnalyzeRawEmlCommand = new RelayCommand(() => { AnalyzeRawEml(); return Task.CompletedTask; });
        AuditRootCertsCommand = new RelayCommand(AuditRootCertsAsync);
        AskAiAboutSelectedProcessCommand = new RelayCommand(() => { AskAiAboutSelectedProcess(); return Task.CompletedTask; });
    }

    // Collections
    public ObservableCollection<SiemCorrelationAlert> SiemIncidents { get; } = new();
    public ObservableCollection<SiemEventEntry> SiemEvents { get; } = new();
    public ObservableCollection<SigmaRuleDefinition> SigmaRules { get; } = new();
    public ObservableCollection<SigmaRuleMatch> SigmaMatches { get; } = new();
    public ObservableCollection<ProcessTreeNode> Processes { get; } = new();
    public ObservableCollection<string> SoarExecutionLogs { get; } = new();
    public ObservableCollection<string> EmlFindings { get; } = new();
    public ObservableCollection<string> EmlUrls { get; } = new();
    public ObservableCollection<RootCertificateAuditItem> RootCerts { get; } = new();

    // Commands
    public ICommand RunSiemCommand { get; }
    public ICommand RunSigmaScanCommand { get; }
    public ICommand CaptureProcessTreeCommand { get; }
    public ICommand KillSelectedProcessCommand { get; }
    public ICommand SaveSoarConfigCommand { get; }
    public ICommand ExecuteSoarCommand { get; }
    public ICommand AnalyzeRawEmlCommand { get; }
    public ICommand AuditRootCertsCommand { get; }
    public ICommand AskAiAboutSelectedProcessCommand { get; }

    public string SiemSummary { get => _siemSummary; set => SetProperty(ref _siemSummary, value); }
    public string SigmaSummary { get => _sigmaSummary; set => SetProperty(ref _sigmaSummary, value); }
    public string ProcTreeSummary { get => _procTreeSummary; set => SetProperty(ref _procTreeSummary, value); }
    public ProcessTreeNode? SelectedProcess { get => _selectedProcess; set => SetProperty(ref _selectedProcess, value); }

    public bool SoarAutoKill { get => _soarAutoKill; set => SetProperty(ref _soarAutoKill, value); }
    public bool SoarAutoFirewall { get => _soarAutoFirewall; set => SetProperty(ref _soarAutoFirewall, value); }
    public bool SoarAutoQuarantine { get => _soarAutoQuarantine; set => SetProperty(ref _soarAutoQuarantine, value); }
    public bool SoarGenerateEvidence { get => _soarGenerateEvidence; set => SetProperty(ref _soarGenerateEvidence, value); }
    public string SoarTargetPidText { get => _soarTargetPidText; set => SetProperty(ref _soarTargetPidText, value); }
    public string SoarTargetPath { get => _soarTargetPath; set => SetProperty(ref _soarTargetPath, value); }
    public string SoarReason { get => _soarReason; set => SetProperty(ref _soarReason, value); }
    public string SoarSummary { get => _soarSummary; set => SetProperty(ref _soarSummary, value); }

    public string EmlInputText { get => _emlInputText; set => SetProperty(ref _emlInputText, value); }
    public string EmlSummary { get => _emlSummary; set => SetProperty(ref _emlSummary, value); }
    public string EmlMetaHeader { get => _emlMetaHeader; set => SetProperty(ref _emlMetaHeader, value); }

    public string RootCertSummary { get => _rootCertSummary; set => SetProperty(ref _rootCertSummary, value); }

    public async Task RunSiemAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _siem.CollectAndCorrelateAsync(50);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            SiemIncidents.Clear();
            foreach (var inc in res.Value.Alerts) SiemIncidents.Add(inc);
            SiemEvents.Clear();
            foreach (var ev in res.Value.RecentEvents.Take(80)) SiemEvents.Add(ev);

            SiemSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task RunSigmaScanAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            RefreshSigmaRulesList();
            var res = await _sigma.ScanWindowsEventsAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            SigmaMatches.Clear();
            foreach (var m in res.Value.Matches) SigmaMatches.Add(m);
            SigmaSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task ImportSigmaYamlAsync(string filePath)
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _sigma.ImportYamlRuleAsync(filePath);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            RefreshSigmaRulesList();
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task CaptureProcessTreeAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _procTree.CaptureProcessTreeAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            Processes.Clear();
            foreach (var p in res.Value.Processes) Processes.Add(p);
            ProcTreeSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    private void KillSelectedProcess()
    {
        ClearMessages();
        if (SelectedProcess is null)
        {
            ErrorMessage = "Select a process row from the Process Tree first.";
            return;
        }
        var res = _procTree.KillProcessTree(SelectedProcess.ProcessId);
        if (res.Success)
        {
            StatusMessage = res.Message;
            Processes.Remove(SelectedProcess);
            SelectedProcess = null;
        }
        else ErrorMessage = res.Message;
    }

    private void AskAiAboutSelectedProcess()
    {
        if (SelectedProcess is null) return;
        _aiTriage.SendToBecettiAi(
            $"Analyze this live Windows process from BECETTI Process Tree Hunter:\n" +
            $"Process: {SelectedProcess.ProcessName} (PID {SelectedProcess.ProcessId})\n" +
            $"Parent: {SelectedProcess.ParentName} (PPID {SelectedProcess.ParentProcessId})\n" +
            $"Signed: {SelectedProcess.IsSigned}\nPath: {SelectedProcess.ExecutablePath}\n" +
            $"CommandLine: {SelectedProcess.CommandLine}\nAnomaly: {SelectedProcess.AnomalyReason}\n" +
            $"Assess whether it is benign or malicious and recommend containment steps.");
    }

    public async Task InitializeAsync()
    {
        var res = await _soar.LoadConfigAsync();
        if (res.Success) LoadSoarConfig();
    }

    private void LoadSoarConfig()
    {
        var cfg = _soar.CurrentConfig;
        SoarAutoKill = cfg.KillMaliciousProcess;
        SoarAutoFirewall = cfg.BlockExecutableInFirewall;
        SoarAutoQuarantine = cfg.AutoQuarantineOnCritical;
        SoarGenerateEvidence = cfg.GenerateForensicEvidenceZip;
    }

    public async Task SaveSoarConfigAsync()
    {
        ClearMessages();
        var cfg = new SoarPlaybookConfig
        {
            Enabled = true,
            KillMaliciousProcess = SoarAutoKill,
            BlockExecutableInFirewall = SoarAutoFirewall,
            AutoQuarantineOnCritical = SoarAutoQuarantine,
            GenerateForensicEvidenceZip = SoarGenerateEvidence
        };
        var res = await _soar.SaveConfigAsync(cfg);
        if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
    }

    public async Task ExecuteSoarAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            await SaveSoarConfigAsync();
            int? pid = int.TryParse(SoarTargetPidText?.Trim(), out var parsed) ? parsed : null;
            var res = await _soar.ExecuteContainmentPlaybookAsync(
                string.IsNullOrWhiteSpace(SoarTargetPath) ? null : SoarTargetPath.Trim(),
                pid,
                string.IsNullOrWhiteSpace(SoarReason) ? "SOC Playbook Execution" : SoarReason.Trim());

            if (res.Value is not null)
            {
                SoarSummary = res.Value.Summary;
                SoarExecutionLogs.Clear();
                foreach (var line in res.Value.StepLogs) SoarExecutionLogs.Add(line);
                if (!string.IsNullOrWhiteSpace(res.Value.EvidenceZipPath))
                    SoarExecutionLogs.Add($"Evidence ZIP: {res.Value.EvidenceZipPath}");
            }
            if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task AnalyzeEmlFileAsync(string emlPath)
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _email.AnalyzeEmlFileAsync(emlPath);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            ApplyEmailReport(res.Value);
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    private void AnalyzeRawEml()
    {
        ClearMessages();
        if (string.IsNullOrWhiteSpace(EmlInputText))
        {
            ErrorMessage = "Paste raw .eml headers/content or use 'Open .EML File…'.";
            return;
        }
        var report = _email.AnalyzeRawEml(EmlInputText, "pasted-email.eml");
        ApplyEmailReport(report);
        StatusMessage = report.Summary;
    }

    private void ApplyEmailReport(EmailForensicsReport r)
    {
        EmlSummary = r.Summary;
        EmlMetaHeader = $"From: {r.FromHeader} | Reply-To: {r.ReplyToHeader} | Subject: {r.Subject} | SPF: {r.SpfStatus} | DKIM: {r.DkimStatus} | DMARC: {r.DmarcStatus}";
        EmlFindings.Clear();
        foreach (var f in r.Findings) EmlFindings.Add(f);
        EmlUrls.Clear();
        foreach (var u in r.ExtractedUrls) EmlUrls.Add(u);
    }

    public async Task AuditRootCertsAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _rootCerts.AuditRootCertificatesAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            RootCerts.Clear();
            foreach (var c in res.Value.Items) RootCerts.Add(c);
            RootCertSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    private void RefreshSigmaRulesList()
    {
        SigmaRules.Clear();
        foreach (var r in _sigma.GetLoadedRules()) SigmaRules.Add(r);
    }
}
