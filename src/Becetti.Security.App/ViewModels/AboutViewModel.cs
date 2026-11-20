using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>About page: version, build and honest capability statements.</summary>
public sealed class AboutViewModel : ViewModelBase
{
    private readonly ISystemInfoService _system;
    private readonly IDefenderService _defender;

    private string _buildText = "Unknown";
    private string _defenderText = "Unknown";

    public AboutViewModel(ISystemInfoService system, IDefenderService defender)
    {
        _system = system;
        _defender = defender;
        LoadCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand LoadCommand { get; }

    public string AppVersion => "1.0.0";
    public string BuildText { get => _buildText; set => SetProperty(ref _buildText, value); }
    public string DefenderText { get => _defenderText; set => SetProperty(ref _defenderText, value); }

    public string CapabilityText =>
        "BECETTI SECURITY uses Microsoft Defender for scanning and threat removal. " +
        "It does not replace Defender, does not run its own antivirus engine, and never invents scan results. " +
        "Cloud features require a configured BECETTI SECURITY API URL (see Settings).";

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        try
        {
            var device = await _system.GetDeviceInfoAsync();
            if (device.Success && device.Value is not null)
            {
                var d = device.Value;
                BuildText = $"{d.OsDescription} (build {d.OsBuild}) · {d.Architecture} · .NET runtime {d.RuntimeVersion}";
            }

            var path = _defender.FindMpCmdRun();
            DefenderText = path is not null
                ? $"Microsoft Defender found at {path}"
                : "Microsoft Defender not found on this device. Scanning features are unavailable.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
