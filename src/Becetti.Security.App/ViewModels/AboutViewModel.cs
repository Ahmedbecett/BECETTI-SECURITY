using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>About page: version, build, native YARA engine status, Defender status, and open-source licenses.</summary>
public sealed class AboutViewModel : ViewModelBase
{
    private readonly ISystemInfoService _system;
    private readonly IDefenderService _defender;
    private readonly IYaraEngineService _yara;

    private string _buildText = "Unknown";
    private string _defenderText = "Unknown";
    private string _yaraText = "Checking native YARA engine...";

    public AboutViewModel(ISystemInfoService system, IDefenderService defender, IYaraEngineService yara)
    {
        _system = system;
        _defender = defender;
        _yara = yara;
        LoadCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand LoadCommand { get; }

    public string AppVersion => "1.0.0";
    public string BuildText { get => _buildText; set => SetProperty(ref _buildText, value); }
    public string DefenderText { get => _defenderText; set => SetProperty(ref _defenderText, value); }
    public string YaraText { get => _yaraText; set => SetProperty(ref _yaraText, value); }

    public string CapabilityText =>
        "BECETTI SECURITY integrates the official open-source YARA engine (https://github.com/VirusTotal/yara, Windows x64) " +
        "as a real local malware detection engine alongside Microsoft Defender (MpCmdRun / PowerShell cmdlets). " +
        "All YARA rules (.yar/.yara) are validated and compiled locally before scanning, and BECETTI SECURITY never invents or simulates scan results.";

    public string YaraLicenseText =>
        "YARA — Copyright (c) 2007-2016. The YARA Authors. All Rights Reserved. " +
        "Licensed under the BSD 3-Clause License (see THIRD-PARTY-LICENSES\\YARA-LICENSE.txt). " +
        "Official repository: https://github.com/VirusTotal/yara · Documentation: https://yara.readthedocs.io/";

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

            var yaraInfo = await _yara.GetEngineInfoAsync();
            if (yaraInfo.Success && yaraInfo.Value is not null && yaraInfo.Value.IsAvailable)
            {
                var y = yaraInfo.Value;
                YaraText = $"Native YARA {y.Version} ({y.Architecture}) — {y.ValidRuleFiles} valid rule file(s) ({y.ActiveRuleCount} rules)";
            }
            else
            {
                YaraText = yaraInfo.Message;
            }

            var path = _defender.FindMpCmdRun();
            DefenderText = path is not null
                ? $"Microsoft Defender found at {path}"
                : "Microsoft Defender not found on this device (Native YARA Engine remains available for local scans).";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
