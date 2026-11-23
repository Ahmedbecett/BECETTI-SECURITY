using System.Collections.ObjectModel;
using System.Windows.Input;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Enterprise Infrastructure &amp; Compliance Hub ViewModel powering 6 modules:
/// #2 LAN Device Discovery &amp; Port Auditor, #10 Live DNS Threat Logger &amp; Per-App Net,
/// #3 Deep Privacy &amp; Traces Cleaner, #6 Encrypted File &amp; Folder Vault Pro,
/// #11 Multi-Device Cloud Fleet Dashboard, and #12 CIS/NIST/ISO Compliance Center.
/// </summary>
public sealed class InfrastructureComplianceViewModel : ViewModelBase
{
    private readonly ILanDiscoveryService _lan;
    private readonly INetworkDnsMonitorService _dnsNet;
    private readonly IPrivacyCleanerService _cleaner;
    private readonly IVaultProService _vault;
    private readonly IFleetDashboardService _fleet;
    private readonly IComplianceCenterService _compliance;
    private readonly ISettingsService _settings;

    // #2 LAN
    private string _lanSummary = "Click 'Scan LAN & Local Ports' to inspect real ARP neighbors and exposed listening ports (RDP, SMB, WinRM).";
    // #10 DNS & Apps
    private string _dnsSummary = "Click 'Audit DNS Cache & App Connections' to cross-check live DNS entries against abuse.ch URLhaus.";
    // #3 Privacy Cleaner
    private string _cleanerSummary = "Click 'Scan Digital Traces' to measure Windows Temp, Recent Docs, Prefetch, Browser Caches & DNS Cache.";
    // #6 Vault Pro
    private string _vaultSourcePath = string.Empty;
    private string _vaultPassphrase = string.Empty;
    private string _vaultSummary = "AES-256-GCM + PBKDF2-310K encrypted vault for sensitive files and entire folders.";
    private VaultProItem? _selectedVaultItem;
    // #11 Fleet
    private string _fleetSummary = "Click 'Refresh Cloud Fleet' to view real devices registered under your BECETTI Cloud account.";
    private FleetDeviceStatus? _selectedFleetDevice;
    // #12 Compliance
    private string _complianceScoreText = "—";
    private string _complianceSummary = "Click 'Run CIS / NIST Audit' to evaluate live endpoint compliance and export audit reports.";
    private ComplianceAuditReport? _lastComplianceReport;

    public InfrastructureComplianceViewModel(
        ILanDiscoveryService lan,
        INetworkDnsMonitorService dnsNet,
        IPrivacyCleanerService cleaner,
        IVaultProService vault,
        IFleetDashboardService fleet,
        IComplianceCenterService compliance,
        ISettingsService settings)
    {
        _lan = lan;
        _dnsNet = dnsNet;
        _cleaner = cleaner;
        _vault = vault;
        _fleet = fleet;
        _compliance = compliance;
        _settings = settings;

        ScanLanCommand = new RelayCommand(ScanLanAsync);
        AuditDnsNetCommand = new RelayCommand(AuditDnsNetAsync);
        ScanTracesCommand = new RelayCommand(ScanTracesAsync);
        CleanSelectedTracesCommand = new RelayCommand(CleanSelectedTracesAsync);
        RefreshVaultCommand = new RelayCommand(RefreshVaultAsync);
        SealVaultItemCommand = new RelayCommand(SealVaultItemAsync);
        DeleteVaultItemCommand = new RelayCommand(DeleteSelectedVaultItemAsync);
        GeneratePasswordCommand = new RelayCommand(() => { GenerateStrongPassword(); return Task.CompletedTask; });
        LoadFleetCommand = new RelayCommand(LoadFleetAsync);
        SyncHeartbeatCommand = new RelayCommand(SyncHeartbeatAsync);
        RemoveFleetDeviceCommand = new RelayCommand(RemoveSelectedFleetDeviceAsync);
        RunComplianceCommand = new RelayCommand(RunComplianceAsync);
        ExportComplianceHtmlCommand = new RelayCommand(ExportComplianceHtmlAsync);
        ExportComplianceJsonCommand = new RelayCommand(ExportComplianceJsonAsync);
    }

    // Collections
    public ObservableCollection<LanDeviceInfo> LanDevices { get; } = new();
    public ObservableCollection<ListeningPortInfo> LocalPorts { get; } = new();
    public ObservableCollection<DnsCacheEntryIntel> DnsEntries { get; } = new();
    public ObservableCollection<AppNetworkUsageSummary> AppConnections { get; } = new();
    public ObservableCollection<PrivacyTraceCategory> TraceCategories { get; } = new();
    public ObservableCollection<VaultProItem> VaultItems { get; } = new();
    public ObservableCollection<FleetDeviceStatus> FleetDevices { get; } = new();
    public ObservableCollection<ComplianceControlResult> ComplianceControls { get; } = new();

    // Commands
    public ICommand ScanLanCommand { get; }
    public ICommand AuditDnsNetCommand { get; }
    public ICommand ScanTracesCommand { get; }
    public ICommand CleanSelectedTracesCommand { get; }
    public ICommand RefreshVaultCommand { get; }
    public ICommand SealVaultItemCommand { get; }
    public ICommand DeleteVaultItemCommand { get; }
    public ICommand GeneratePasswordCommand { get; }
    public ICommand LoadFleetCommand { get; }
    public ICommand SyncHeartbeatCommand { get; }
    public ICommand RemoveFleetDeviceCommand { get; }
    public ICommand RunComplianceCommand { get; }
    public ICommand ExportComplianceHtmlCommand { get; }
    public ICommand ExportComplianceJsonCommand { get; }

    public string LanSummary { get => _lanSummary; set => SetProperty(ref _lanSummary, value); }
    public string DnsSummary { get => _dnsSummary; set => SetProperty(ref _dnsSummary, value); }
    public string CleanerSummary { get => _cleanerSummary; set => SetProperty(ref _cleanerSummary, value); }

    public string VaultSourcePath { get => _vaultSourcePath; set => SetProperty(ref _vaultSourcePath, value); }
    public string VaultPassphrase { get => _vaultPassphrase; set => SetProperty(ref _vaultPassphrase, value); }
    public string VaultSummary { get => _vaultSummary; set => SetProperty(ref _vaultSummary, value); }
    public VaultProItem? SelectedVaultItem { get => _selectedVaultItem; set => SetProperty(ref _selectedVaultItem, value); }

    public string FleetSummary { get => _fleetSummary; set => SetProperty(ref _fleetSummary, value); }
    public FleetDeviceStatus? SelectedFleetDevice { get => _selectedFleetDevice; set => SetProperty(ref _selectedFleetDevice, value); }

    public string ComplianceScoreText { get => _complianceScoreText; set => SetProperty(ref _complianceScoreText, value); }
    public string ComplianceSummary { get => _complianceSummary; set => SetProperty(ref _complianceSummary, value); }

    public async Task ScanLanAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _lan.ScanLocalNetworkAndPortsAsync(activePingSweep: true);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            LanDevices.Clear();
            foreach (var d in res.Value.Devices) LanDevices.Add(d);
            LocalPorts.Clear();
            foreach (var p in res.Value.ListeningPorts) LocalPorts.Add(p);

            LanSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task AuditDnsNetAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _dnsNet.AuditDnsCacheAndAppsAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            DnsEntries.Clear();
            foreach (var d in res.Value.DnsEntries) DnsEntries.Add(d);
            AppConnections.Clear();
            foreach (var a in res.Value.AppSummaries) AppConnections.Add(a);

            DnsSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task ScanTracesAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _cleaner.ScanReclaimableTracesAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            TraceCategories.Clear();
            foreach (var c in res.Value) TraceCategories.Add(c);
            CleanerSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task CleanSelectedTracesAsync()
    {
        if (IsBusy) return;
        var selected = TraceCategories.Where(c => c.IsSelected).ToList();
        if (selected.Count == 0) { ErrorMessage = "Scan traces and select at least one category to clean."; return; }

        IsBusy = true; ClearMessages();
        try
        {
            var res = await _cleaner.CleanSelectedCategoriesAsync(selected, flushDnsCache: true);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            CleanerSummary = res.Value.Summary;
            StatusMessage = res.Message;
            // Re-scan to show real remaining bytes
            var rescan = await _cleaner.ScanReclaimableTracesAsync();
            if (rescan.Success && rescan.Value is not null)
            {
                TraceCategories.Clear();
                foreach (var c in rescan.Value) TraceCategories.Add(c);
            }
        }
        finally { IsBusy = false; }
    }

    public async Task RefreshVaultAsync()
    {
        var res = await _vault.ListItemsAsync();
        if (res.Success && res.Value is not null)
        {
            VaultItems.Clear();
            foreach (var item in res.Value) VaultItems.Add(item);
            VaultSummary = res.Message;
        }
    }

    public async Task SealVaultItemAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _vault.SealFileOrFolderAsync(VaultSourcePath, VaultPassphrase);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            StatusMessage = res.Message;
            VaultSourcePath = string.Empty;
            await RefreshVaultAsync();
        }
        finally { IsBusy = false; }
    }

    public async Task UnsealSelectedVaultItemAsync(string destinationFolder)
    {
        if (IsBusy) return;
        if (SelectedVaultItem is null) { ErrorMessage = "Select a vault item to decrypt."; return; }
        if (string.IsNullOrWhiteSpace(VaultPassphrase)) { ErrorMessage = "Enter the vault passphrase to decrypt."; return; }

        IsBusy = true; ClearMessages();
        try
        {
            var res = await _vault.UnsealItemAsync(SelectedVaultItem.Id, VaultPassphrase, destinationFolder);
            if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task DeleteSelectedVaultItemAsync()
    {
        if (IsBusy || SelectedVaultItem is null) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _vault.DeleteItemAsync(SelectedVaultItem.Id);
            if (res.Success) { StatusMessage = res.Message; await RefreshVaultAsync(); }
            else ErrorMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    private void GenerateStrongPassword()
    {
        VaultPassphrase = _vault.GenerateStrongPassword(24);
        StatusMessage = "Generated 24-character cryptographically strong password (CSPRNG). Save it safely before sealing!";
    }

    public async Task LoadFleetAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _fleet.LoadFleetAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            FleetDevices.Clear();
            foreach (var d in res.Value.Devices) FleetDevices.Add(d);
            FleetSummary = res.Value.Summary;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task SyncHeartbeatAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _fleet.SyncCurrentDeviceHeartbeatAsync();
            if (!res.Success) { ErrorMessage = res.Message; return; }
            StatusMessage = res.Message;
            var reload = await _fleet.LoadFleetAsync();
            if (reload.Success && reload.Value is not null)
            {
                FleetDevices.Clear();
                foreach (var d in reload.Value.Devices) FleetDevices.Add(d);
                FleetSummary = reload.Value.Summary;
            }
        }
        finally { IsBusy = false; }
    }

    public async Task RemoveSelectedFleetDeviceAsync()
    {
        if (IsBusy || SelectedFleetDevice is null) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _fleet.RemoveFleetDeviceAsync(SelectedFleetDevice.DeviceId);
            if (res.Success) { StatusMessage = res.Message; FleetDevices.Remove(SelectedFleetDevice); SelectedFleetDevice = null; }
            else ErrorMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task RunComplianceAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _compliance.RunComplianceAuditAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            _lastComplianceReport = res.Value;
            ComplianceScoreText = $"{res.Value.ComplianceScorePercent}%";
            ComplianceSummary = res.Value.Summary;
            ComplianceControls.Clear();
            foreach (var c in res.Value.Controls) ComplianceControls.Add(c);
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task ExportComplianceHtmlAsync()
    {
        if (_lastComplianceReport is null) { ErrorMessage = "Run the CIS / NIST Compliance Audit first."; return; }
        var outPath = Path.Combine(_settings.DataDirectory, "reports", $"becetti-compliance-{DateTime.UtcNow:yyyyMMdd-HHmmss}.html");
        var res = await _compliance.ExportComplianceHtmlReportAsync(_lastComplianceReport, outPath);
        if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
    }

    public async Task ExportComplianceJsonAsync()
    {
        if (_lastComplianceReport is null) { ErrorMessage = "Run the CIS / NIST Compliance Audit first."; return; }
        var outPath = Path.Combine(_settings.DataDirectory, "reports", $"becetti-compliance-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        var res = await _compliance.ExportComplianceJsonReportAsync(_lastComplianceReport, outPath);
        if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
    }
}
