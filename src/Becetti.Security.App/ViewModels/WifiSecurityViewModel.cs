using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Wi-Fi Security page: the real currently-connected Wi-Fi network's security details.</summary>
public sealed class WifiSecurityViewModel : ViewModelBase
{
    private readonly IWifiSecurityService _wifi;

    private WifiSecurityInfo _info = new();

    public WifiSecurityViewModel(IWifiSecurityService wifi)
    {
        _wifi = wifi;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

    public WifiSecurityInfo Info { get => _info; set => SetProperty(ref _info, value); }

    public string Summary => !Info.Connected
        ? "Not connected to a Wi-Fi network."
        : $"{Info.Ssid ?? "(hidden)"} — {Info.AuthenticationType ?? "Unknown"} / {Info.CipherType ?? "Unknown"}" +
          (Info.SignalPercent is { } signal ? $", signal {signal}%" : string.Empty);

    public string SecuritySummary => Info.IsStronglySecured switch
    {
        true => "This network uses strong (WPA2/WPA3) encryption.",
        false => "This network does not use strong encryption — avoid sensitive logins on it.",
        null => "Encryption strength could not be determined."
    };

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _wifi.GetCurrentNetworkSecurityAsync();
            if (result.Success && result.Value is not null)
            {
                Info = result.Value;
                StatusMessage = result.Message;
            }
            else
            {
                ErrorMessage = result.Message;
            }

            OnPropertyChanged(nameof(Summary));
            OnPropertyChanged(nameof(SecuritySummary));
        }
        finally
        {
            IsBusy = false;
        }
    }
}
