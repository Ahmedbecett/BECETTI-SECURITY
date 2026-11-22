using Becetti.Security.Core.Services;
using Windows.Media.Core;
using Windows.Media.Playback;

namespace Becetti.Security.App.Services;

/// <summary>Genuine event cues only — never played to simulate activity that isn't happening.</summary>
public enum SoundCue
{
    ScanCompleted,
    UpdateCompleted,
    Warning,
    Critical
}

/// <summary>
/// Plays the official Windows system notification sounds that already ship with every
/// Windows 10/11 install (%windir%\Media). No bundled audio files, no third-party sound
/// library — purely decorative and fully gated by Settings.EnableSounds. Any failure
/// (missing file, no audio device, non-Windows host) is swallowed silently: sound is
/// never allowed to break or block a real security action.
/// </summary>
public sealed class SoundService : IDisposable
{
    private readonly ISettingsService _settings;
    private readonly MediaPlayer _player = new();

    public SoundService(ISettingsService settings)
    {
        _settings = settings;
    }

    public void Play(SoundCue cue)
    {
        if (!_settings.Current.EnableSounds)
            return;

        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            var fileName = cue switch
            {
                SoundCue.ScanCompleted => "Windows Notify System Generic.wav",
                SoundCue.UpdateCompleted => "Windows Notify Calendar.wav",
                SoundCue.Warning => "Windows Exclamation.wav",
                SoundCue.Critical => "Windows Critical Stop.wav",
                _ => "Windows Notify System Generic.wav"
            };

            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Media", fileName);
            if (!File.Exists(path))
                return;

            _player.Source = MediaSource.CreateFromUri(new Uri(path));
            _player.Play();
        }
        catch
        {
            // Sound is purely decorative; it must never surface an error or interrupt a real action.
        }
    }

    public void Dispose() => _player.Dispose();
}
