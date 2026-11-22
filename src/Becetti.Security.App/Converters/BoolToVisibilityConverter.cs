using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Becetti.Security.App.Converters;

/// <summary>bool -> Visibility. Pass ConverterParameter="Invert" to flip it.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var flag = value is bool b && b;
        if (string.Equals(parameter as string, "Invert", StringComparison.OrdinalIgnoreCase))
            flag = !flag;
        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
