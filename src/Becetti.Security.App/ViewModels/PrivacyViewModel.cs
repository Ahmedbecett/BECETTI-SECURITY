using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Privacy &amp; Network page: measured network/TLS checks plus configuration
/// checks (UAC, firewall, real-time protection). Recommendations are derived
/// from measured values only.
/// </summary>
public sealed class PrivacyViewModel : ViewModelBase
{
    private readonly ISystemInfoService _system;
    private readonly IDefenderService _defender;
    private readonly ISettingsService _settings;

    private string _networkText = "Not checked yet.";
    private string _tlsText = "Not checked yet.";
    private string _configText = "Not checked yet.";

    public PrivacyViewModel(ISystemInfoService system, IDefenderService defender, ISettingsService settings)
    {
        _system = system;
        _defender = defender;
        _settings = settings;
        RunChecksCommand = new RelayCommand(RunChecksAsync);
    }

    public ObservableCollection<string> Recommendations { get; } = new();
    public ObservableCollection<PrivacyPermissionInfo> Permissions { get; } = new();

    public RelayCommand RunChecksCommand { get; }

    public string NetworkText { get => _networkText; set => SetProperty(ref _networkText, value); }
    public string TlsText { get => _tlsText; set => SetProperty(ref _tlsText, value); }
    public string ConfigText { get => _configText; set => SetProperty(ref _configText, value); }

    public async Task RunChecksAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        Recommendations.Clear();
        Permissions.Clear();
        try
        {
            var permissions = await _system.GetPrivacyPermissionsAsync();
            if (permissions.Success && permissions.Value is not null)
            {
                foreach (var permission in permissions.Value)
                    Permissions.Add(permission);
            }

            var network = await _system.CheckNetworkAsync(_settings.Current.ApiBaseUrl);
            if (network.Success && network.Value is not null)
            {
                var n = network.Value;
                NetworkText = $"Network: {(n.NetworkAvailable ? "Available" : "Unavailable")} · Adapter: {n.ActiveAdapter ?? "unknown"} · DNS: {(n.DnsResolvable ? "OK" : "Not verified")}";
                TlsText = n.TlsDetail ?? "TLS not tested.";
            }
            else
            {
                NetworkText = "Network check failed.";
                ErrorMessage = network.Message;
            }

            var device = await _system.GetDeviceInfoAsync();
            var status = await _defender.GetStatusAsync();
            var firewall = await _defender.GetFirewallAsync();

            var configLines = new List<string>();
            if (device.Success && device.Value is not null)
            {
                configLines.Add($"UAC: {(device.Value.UacEnabled ? "Enabled" : "Disabled")}");
                if (!device.Value.UacEnabled)
                    Recommendations.Add("Enable User Account Control (UAC) in Windows Security settings.");
            }

            if (status.Success && status.Value is not null)
            {
                configLines.Add($"Real-time protection: {(status.Value.RealTimeProtectionEnabled ? "On" : "Off")}");
                if (!status.Value.RealTimeProtectionEnabled)
                    Recommendations.Add("Turn on real-time protection in the Real-Time Protection page.");
            }

            if (firewall.Success && firewall.Value is not null)
            {
                var off = firewall.Value.Where(f => !f.Enabled).Select(f => f.Name).ToList();
                configLines.Add(off.Count == 0 ? "Firewall: On for all profiles" : $"Firewall off for: {string.Join(", ", off)}");
                if (off.Count > 0)
                    Recommendations.Add("Turn on Windows Firewall for all network profiles.");
            }

            ConfigText = string.Join("\n", configLines);
            if (Recommendations.Count == 0)
                Recommendations.Add("No configuration issues found in the checks above.");

            StatusMessage = "Privacy and network checks completed.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
