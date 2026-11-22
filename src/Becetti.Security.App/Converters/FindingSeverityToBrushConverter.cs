using Becetti.Security.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace Becetti.Security.App.Converters;

/// <summary>Maps a Vulnerability Advisor finding's verified severity to the matching status brush.</summary>
public sealed class FindingSeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var severity = value is FindingSeverity s ? s : FindingSeverity.Unknown;
        var key = severity switch
        {
            FindingSeverity.Good => "AccentGreenBrush",
            FindingSeverity.Info => "TextSecondaryBrush",
            FindingSeverity.Low => "WarningBrush",
            FindingSeverity.Medium => "WarningBrush",
            FindingSeverity.High => "DangerBrush",
            _ => "TextSecondaryBrush"
        };

        return Application.Current.Resources.TryGetValue(key, out var brush) && brush is Brush b
            ? b
            : (Brush)Application.Current.Resources["TextSecondaryBrush"];
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
