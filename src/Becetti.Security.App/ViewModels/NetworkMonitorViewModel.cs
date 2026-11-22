using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Network Monitor page: real network adapters, real active TCP connections,
/// firewall profile state, and real per-application Windows Firewall blocking/unblocking.
/// </summary>
public sealed class NetworkMonitorViewModel : ViewModelBase
{
    private readonly INetworkMonitorService _network;
    private readonly IDefenderService _defender;
    private readonly IPerAppFirewallService _perAppFirewall;

    private string _firewallText = "Not checked yet.";
    private string _appPathToBlock = string.Empty;

    public NetworkMonitorViewModel(
        INetworkMonitorService network,
        IDefenderService defender,
        IPerAppFirewallService perAppFirewall)
    {
        _network = network;
        _defender = defender;
        _perAppFirewall = perAppFirewall;
        RefreshCommand = new RelayCommand(LoadAsync);
        BlockAppCommand = new RelayCommand(BlockAppAsync, () => !string.IsNullOrWhiteSpace(AppPathToBlock));
    }

    public ObservableCollection<NetworkAdapterInfo> Adapters { get; } = new();
    public ObservableCollection<NetworkConnectionInfo> Connections { get; } = new();
    public ObservableCollection<FirewallBlockedApp> BlockedApps { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand BlockAppCommand { get; }

    public string FirewallText { get => _firewallText; set => SetProperty(ref _firewallText, value); }

    public string AppPathToBlock
    {
        get => _appPathToBlock;
        set
        {
            if (SetProperty(ref _appPathToBlock, value))
                BlockAppCommand.RaiseCanExecuteChanged();
        }
    }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var adaptersResult = await _network.GetAdaptersAsync();
            Adapters.Clear();
            if (adaptersResult.Success && adaptersResult.Value is not null)
            {
                foreach (var adapter in adaptersResult.Value)
                    Adapters.Add(adapter);
            }
            else
            {
                ErrorMessage = adaptersResult.Message;
            }

            var connectionsResult = await _network.GetActiveConnectionsAsync();
            Connections.Clear();
            if (connectionsResult.Success && connectionsResult.Value is not null)
            {
                foreach (var connection in connectionsResult.Value
                             .OrderByDescending(c => !string.Equals(c.State, "Listen", StringComparison.OrdinalIgnoreCase))
                             .ThenBy(c => c.LocalPort))
                {
                    Connections.Add(connection);
                }
            }
            else if (string.IsNullOrWhiteSpace(ErrorMessage))
            {
                ErrorMessage = connectionsResult.Message;
            }

            var firewall = await _defender.GetFirewallAsync();
            FirewallText = firewall.Success && firewall.Value is not null
                ? string.Join("  ·  ", firewall.Value.Select(p => $"{p.Name}: {(p.Enabled ? "On" : "Off")}"))
                : "Unknown";

            await ReloadBlockedAppsAsync();

            StatusMessage = $"{Adapters.Count} adapter(s), {Connections.Count} active connection(s), {BlockedApps.Count} blocked app rule(s).";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task BlockAppAsync()
    {
        if (string.IsNullOrWhiteSpace(AppPathToBlock))
            return;

        ClearMessages();
        var res = await _perAppFirewall.BlockApplicationAsync(AppPathToBlock.Trim());
        if (res.Success)
        {
            StatusMessage = res.Message;
            AppPathToBlock = string.Empty;
            await ReloadBlockedAppsAsync();
        }
        else
        {
            ErrorMessage = res.Message;
        }
    }

    public async Task UnblockRuleAsync(string ruleName)
    {
        ClearMessages();
        var res = await _perAppFirewall.UnblockApplicationAsync(ruleName);
        if (res.Success)
        {
            StatusMessage = res.Message;
            await ReloadBlockedAppsAsync();
        }
        else
        {
            ErrorMessage = res.Message;
        }
    }

    private async Task ReloadBlockedAppsAsync()
    {
        BlockedApps.Clear();
        var res = await _perAppFirewall.GetBlockedAppsAsync();
        if (res.Success && res.Value is not null)
        {
            foreach (var app in res.Value)
                BlockedApps.Add(app);
        }
    }
}
