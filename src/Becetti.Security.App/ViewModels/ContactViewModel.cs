using System.Text;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// "Contact Becetti" support flow. BECETTI SECURITY never sends anything on
/// its own: this view model only ever prepares a draft and hands it to the
/// user's own default email application via the system "mailto:" handler.
/// Nothing leaves the device until the user presses Send inside their own
/// mail client — that is the explicit approval step the product requires.
/// Diagnostics (device/Defender info) are attached to the draft only when
/// the user turns on "Include diagnostics" below; it is OFF by default.
/// </summary>
public sealed class ContactViewModel : ViewModelBase
{
    private readonly ISettingsService _settings;
    private readonly ISystemInfoService _system;
    private readonly IDefenderService _defender;

    private string _subject = string.Empty;
    private string _message = string.Empty;
    private bool _includeDiagnostics;

    public ContactViewModel(ISettingsService settings, ISystemInfoService system, IDefenderService defender)
    {
        _settings = settings;
        _system = system;
        _defender = defender;
        PrepareEmailCommand = new RelayCommand(PrepareEmailAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(Message));
    }

    public RelayCommand PrepareEmailCommand { get; }

    public string SupportEmail => _settings.Current.SupportEmail;

    public string Subject
    {
        get => _subject;
        set => SetProperty(ref _subject, value);
    }

    public string Message
    {
        get => _message;
        set
        {
            if (SetProperty(ref _message, value))
                PrepareEmailCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>OFF by default. Real device/Defender data is attached to the draft only with this explicit opt-in.</summary>
    public bool IncludeDiagnostics
    {
        get => _includeDiagnostics;
        set => SetProperty(ref _includeDiagnostics, value);
    }

    private async Task PrepareEmailAsync()
    {
        if (IsBusy || string.IsNullOrWhiteSpace(Message))
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var body = new StringBuilder(Message.Trim());

            if (IncludeDiagnostics)
            {
                body.AppendLine();
                body.AppendLine();
                body.AppendLine("--- Diagnostics (review before sending) ---");
                body.AppendLine(await BuildDiagnosticsAsync());
            }

            var subject = string.IsNullOrWhiteSpace(Subject) ? "BECETTI SECURITY support request" : Subject.Trim();
            var uri = $"mailto:{Uri.EscapeDataString(SupportEmail)}?subject={Uri.EscapeDataString(subject)}&body={Uri.EscapeDataString(body.ToString())}";

            if (OperatingSystem.IsWindows())
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = uri,
                    UseShellExecute = true
                };
                System.Diagnostics.Process.Start(startInfo);
                StatusMessage = "Your default email app opened with this message as a draft. Nothing is sent until you press Send there.";
            }
            else
            {
                ErrorMessage = "Opening the email app is only supported on Windows.";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not open your email app: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task<string> BuildDiagnosticsAsync()
    {
        var lines = new List<string>();

        try
        {
            var device = await _system.GetDeviceInfoAsync();
            if (device.Success && device.Value is not null)
            {
                var d = device.Value;
                lines.Add($"OS: {d.OsDescription} (build {d.OsBuild}) · {d.Architecture} · runtime {d.RuntimeVersion}");
            }
            else
            {
                lines.Add("OS: could not be read.");
            }
        }
        catch
        {
            lines.Add("OS: could not be read.");
        }

        try
        {
            var status = await _defender.GetStatusAsync();
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                lines.Add($"Defender — antivirus: {s.AntivirusEnabled}, real-time: {s.RealTimeProtectionEnabled}, tamper: {s.TamperProtectionEnabled}, cloud level: {s.CloudProtectionLevel}");
            }
            else
            {
                lines.Add("Defender status: could not be verified.");
            }
        }
        catch
        {
            lines.Add("Defender status: could not be verified.");
        }

        lines.Add("BECETTI SECURITY v1.0.0");
        return string.Join(Environment.NewLine, lines);
    }
}
