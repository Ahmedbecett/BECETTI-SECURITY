using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Becetti.Security.App.Converters;

/// <summary>True (user message) aligns right; false (BECETTI AI message) aligns left.</summary>
public sealed class AiMessageAlignmentConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is bool isFromUser && isFromUser ? HorizontalAlignment.Right : HorizontalAlignment.Left;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
