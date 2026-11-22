using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Network Monitor page: real network adapters, real active TCP connections
/// and listening ports (Get-NetTCPConnection), and real firewall profile
/// state (reused from IDefenderService, not duplicated). BECETTI SECURITY
/// never labels a connection "suspicious" on its own — it shows Windows'
/// own verified list so the user can judge what is actually talking to
/// the network right now.
/// </summary>
public sealed class NetworkMonitorViewModel : ViewModelBase
{
    private readonly INetworkMonitorService _network;
    private readonly IDefenderService _defender;

    private string _firewallText = "Not checked yet.";

    public NetworkMonitorViewModel(INetworkMonitorService network, IDefenderService defender)
    {
        _network = network;
        _defender = defender;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public ObservableCollection<NetworkAdapterInfo> Adapters { get; } = new();
    public ObservableCollection<NetworkConnectionInfo> Connections { get; } = new();

    public RelayCommand RefreshCommand { get; }

    public string FirewallText { get => _firewallText; set => SetProperty(ref _firewallText, value); }

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
                // Established/talking connections first — that is the actually interesting
                // "who is my PC talking to right now" view; pure listeners follow.
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

            StatusMessage = $"{Adapters.Count} adapter(s), {Connections.Count} active connection(s)/listener(s).";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
