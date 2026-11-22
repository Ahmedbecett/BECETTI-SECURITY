using System.Text;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Emergency Center: a single page for "something feels wrong" moments. Every
/// value shown is read live from Defender/PC Health at the time the page
/// opens; the quick actions only ever open real, official Windows surfaces
/// (Windows Security, Backup settings) or an in-app page — nothing here
/// performs its own remediation.
/// </summary>
public sealed class EmergencyCenterViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly IPcHealthService _pcHealth;

    private ProtectionLevel _protectionLevel = ProtectionLevel.Unknown;
    private int _threatCount;
    private string _diagnosticSummary = string.Empty;

    public EmergencyCenterViewModel(IDefenderService defender, IPcHealthService pcHealth)
    {
        _defender = defender;
        _pcHealth = pcHealth;
        RefreshCommand = new RelayCommand(LoadAsync);
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);
        OpenBackupSettingsCommand = new RelayCommand(OpenBackupSettings);
        GenerateDiagnosticSummaryCommand = new RelayCommand(GenerateDiagnosticSummaryAsync);
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public RelayCommand OpenBackupSettingsCommand { get; }
    public RelayCommand GenerateDiagnosticSummaryCommand { get; }

    public ProtectionLevel ProtectionLevel
    {
        get => _protectionLevel;
        private set
        {
            if (SetProperty(ref _protectionLevel, value))
            {
                OnPropertyChanged(nameof(ProtectionHeadline));
                OnPropertyChanged(nameof(IsAtRisk));
            }
        }
    }

    public int ThreatCount
    {
        get => _threatCount;
        private set => SetProperty(ref _threatCount, value);
    }

    public string DiagnosticSummary
    {
        get => _diagnosticSummary;
        private set => SetProperty(ref _diagnosticSummary, value);
    }

    public bool HasDiagnosticSummary => !string.IsNullOrWhiteSpace(DiagnosticSummary);

    public bool IsAtRisk => ProtectionLevel is ProtectionLevel.Danger or ProtectionLevel.Warning || ThreatCount > 0;

    public string ProtectionHeadline => ProtectionLevel switch
    {
        ProtectionLevel.Protected => ThreatCount > 0
            ? $"Protection is active, but Defender reports {ThreatCount} detection(s) needing review."
            : "No active threats or protection gaps were found just now.",
        ProtectionLevel.Warning => "Your protection needs attention right now.",
        ProtectionLevel.Danger => "Your device's antivirus is disabled. Act now.",
        _ => "Protection status could not be verified."
    };

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var status = await _defender.GetStatusAsync();
            ProtectionLevel = ProtectionStatusEvaluator.Evaluate(status.Success ? status.Value : null);

            var threats = await _defender.GetThreatsAsync();
            ThreatCount = threats.Success && threats.Value is not null ? threats.Value.Count : 0;

            StatusMessage = "Emergency Center refreshed from live Defender data.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private Task OpenWindowsSecurity()
    {
        ClearMessages();
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                ErrorMessage = "Windows Security can only be opened on Windows.";
                return Task.CompletedTask;
            }

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "windowsdefender://",
                UseShellExecute = true
            });
            StatusMessage = "Opening Windows Security…";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not open Windows Security: {ex.Message}";
        }

        return Task.CompletedTask;
    }

    /// <summary>Opens the real Windows Settings > Backup page via the official ms-settings: URI scheme.</summary>
    private Task OpenBackupSettings()
    {
        ClearMessages();
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                ErrorMessage = "Backup settings can only be opened on Windows.";
                return Task.CompletedTask;
            }

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "ms-settings:backup",
                UseShellExecute = true
            });
            StatusMessage = "Opening Windows Backup settings…";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not open Backup settings: {ex.Message}";
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Builds a plain-text snapshot from this moment's real Defender/firewall/PC
    /// health reads, for the user to copy and share with support or keep for
    /// their own records. Nothing here is sent anywhere automatically.
    /// </summary>
    private async Task GenerateDiagnosticSummaryAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine($"BECETTI SECURITY diagnostic summary — {DateTimeOffset.Now:yyyy-MM-dd HH:mm}");
            sb.AppendLine();

            var status = await _defender.GetStatusAsync();
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                sb.AppendLine($"Antivirus enabled: {s.AntivirusEnabled}");
                sb.AppendLine($"Real-time protection: {s.RealTimeProtectionEnabled}");
                sb.AppendLine($"Tamper protection: {s.TamperProtectionEnabled}");
                sb.AppendLine($"Running mode: {s.RunningMode}");
                sb.AppendLine($"Security intelligence version: {s.AntivirusSignatureVersion ?? "unknown"} (updated {s.AntivirusSignatureLastUpdated?.ToString("g") ?? "unknown"})");
            }
            else
            {
                sb.AppendLine("Defender status: could not be read.");
            }

            var firewall = await _defender.GetFirewallAsync();
            if (firewall.Success && firewall.Value is not null)
            {
                sb.AppendLine("Firewall: " + string.Join(", ", firewall.Value.Select(f => $"{f.Name}={(f.Enabled ? "On" : "Off")}")));
            }

            var ransomware = await _defender.GetRansomwareProtectionAsync();
            if (ransomware.Success && ransomware.Value is not null)
            {
                sb.AppendLine($"Controlled Folder Access: {ransomware.Value.ControlledFolderAccessState}");
            }

            var health = await _pcHealth.GetSnapshotAsync();
            if (health.Success && health.Value is not null)
            {
                var h = health.Value;
                if (h.Performance.Available)
                    sb.AppendLine($"CPU usage: {h.Performance.CpuUsagePercent}% · Memory usage: {h.Performance.MemoryLoadPercent}%");
                foreach (var disk in h.Disks)
                    sb.AppendLine($"Disk {disk.DisplayName}: {disk.FreePercent}% free");
                foreach (var service in h.Services.Where(sv => !sv.IsRunning))
                    sb.AppendLine($"Service not running: {service.DisplayName}");
            }

            var threats = await _defender.GetThreatsAsync();
            sb.AppendLine($"Active threat detections: {(threats.Success && threats.Value is not null ? threats.Value.Count : 0)}");

            DiagnosticSummary = sb.ToString();
            OnPropertyChanged(nameof(HasDiagnosticSummary));
            StatusMessage = "Diagnostic summary generated from live data. Nothing was sent anywhere.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
