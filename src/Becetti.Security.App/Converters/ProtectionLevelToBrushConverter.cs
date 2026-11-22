using Becetti.Security.Core.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace Becetti.Security.App.Converters;

/// <summary>Maps a verified ProtectionLevel to the matching status brush (green/orange/red/neutral only).</summary>
public sealed class ProtectionLevelToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var level = value is ProtectionLevel l ? l : ProtectionLevel.Unknown;
        var key = level switch
        {
            ProtectionLevel.Protected => "AccentGreenBrush",
            ProtectionLevel.Warning => "WarningBrush",
            ProtectionLevel.Danger => "DangerBrush",
            _ => "TextSecondaryBrush"
        };

        return Application.Current.Resources.TryGetValue(key, out var brush) && brush is Brush b
            ? b
            : (Brush)Application.Current.Resources["TextSecondaryBrush"];
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
