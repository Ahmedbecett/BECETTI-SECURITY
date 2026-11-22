using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace Becetti.Security.App.Converters;

/// <summary>
/// true -> the app's green "good" brush, false -> the app's warning/danger
/// brush. Used for small status dots (security score factors, service run
/// state, disk free-space warnings) where the underlying bool is already a
/// real, verified signal — this converter only chooses a color for it.
/// </summary>
public sealed class BoolToStatusBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var isGood = value is bool b && b;
        var key = isGood ? "AccentGreenBrush" : "WarningBrush";
        return Microsoft.UI.Xaml.Application.Current.Resources.TryGetValue(key, out var brush) && brush is Brush b2
            ? b2
            : new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
