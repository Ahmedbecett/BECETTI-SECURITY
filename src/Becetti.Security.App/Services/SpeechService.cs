using Windows.Media.Core;
using Windows.Media.Playback;
using Windows.Media.SpeechSynthesis;

namespace Becetti.Security.App.Services;

/// <summary>
/// Reads BECETTI AI's replies aloud using the official Windows text-to-speech
/// engine (Windows.Media.SpeechSynthesis) — the same system voices already
/// installed with Windows, no third-party or cloud TTS, no bundled audio.
/// Used only on the BECETTI AI page. Every failure (missing voice pack, no
/// audio device, non-Windows host) is swallowed silently: speech is purely
/// decorative and must never block or break the chat itself.
/// </summary>
public sealed class SpeechService : IDisposable
{
    private readonly MediaPlayer _player = new();
    private SpeechSynthesizer? _synthesizer;

    /// <summary>Raised the moment audio playback actually starts.</summary>
    public event EventHandler? SpeakingStarted;

    /// <summary>Raised when playback ends, fails, or is stopped.</summary>
    public event EventHandler? SpeakingEnded;

    public SpeechService()
    {
        _player.MediaEnded += (_, _) => SpeakingEnded?.Invoke(this, EventArgs.Empty);
        _player.MediaFailed += (_, _) => SpeakingEnded?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Speaks <paramref name="text"/>, preferring an installed system voice
    /// matching <paramref name="languageTag"/> (e.g. "ar-SA", "fr-FR",
    /// "en-US"). Falls back to the default system voice if no matching
    /// language pack is installed — never claims a language it cannot
    /// actually speak.
    /// </summary>
    public async Task SpeakAsync(string text, string languageTag)
    {
        if (string.IsNullOrWhiteSpace(text) || !OperatingSystem.IsWindows())
            return;

        try
        {
            _synthesizer ??= new SpeechSynthesizer();

            var shortTag = languageTag.Split('-')[0];
            var voice = SpeechSynthesizer.AllVoices.FirstOrDefault(v =>
                    v.Language.Equals(languageTag, StringComparison.OrdinalIgnoreCase))
                ?? SpeechSynthesizer.AllVoices.FirstOrDefault(v =>
                    v.Language.StartsWith(shortTag, StringComparison.OrdinalIgnoreCase));

            if (voice is not null)
                _synthesizer.Voice = voice;

            using var stream = await _synthesizer.SynthesizeTextToStreamAsync(text);

            _player.Source = MediaSource.CreateFromStream(stream, stream.ContentType);
            SpeakingStarted?.Invoke(this, EventArgs.Empty);
            _player.Play();
        }
        catch
        {
            // Decorative only: a missing voice pack or audio device must
            // never block or surface an error in the chat.
            SpeakingEnded?.Invoke(this, EventArgs.Empty);
        }
    }

    public void Stop()
    {
        try
        {
            _player.Pause();
        }
        catch
        {
            // Ignore — stopping speech is best-effort.
        }

        SpeakingEnded?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose() => _player.Dispose();
}
