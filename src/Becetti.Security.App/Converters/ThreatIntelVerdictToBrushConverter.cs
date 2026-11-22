using Becetti.Security.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace Becetti.Security.App.Converters;

/// <summary>Maps a real VirusTotal verdict to the matching status brush.</summary>
public sealed class ThreatIntelVerdictToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var verdict = value is ThreatIntelVerdict v ? v : ThreatIntelVerdict.Unknown;
        var key = verdict switch
        {
            ThreatIntelVerdict.Clean => "AccentGreenBrush",
            ThreatIntelVerdict.Suspicious => "WarningBrush",
            ThreatIntelVerdict.Malicious => "DangerBrush",
            _ => "TextSecondaryBrush"
        };

        return Application.Current.Resources.TryGetValue(key, out var brush) && brush is Brush b
            ? b
            : (Brush)Application.Current.Resources["TextSecondaryBrush"];
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
