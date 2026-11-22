using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Becetti.Security.App.Converters;

/// <summary>
/// Visibility helper for "is there anything to show" checks: a null or empty
/// string, or a zero count, collapses the element; anything else shows it.
/// </summary>
public sealed class NotEmptyToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var hasContent = value switch
        {
            null => false,
            string s => !string.IsNullOrWhiteSpace(s),
            int i => i > 0,
            _ => true
        };
        return hasContent ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
