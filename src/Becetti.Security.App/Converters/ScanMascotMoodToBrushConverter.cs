using Becetti.Security.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace Becetti.Security.App.Converters;

/// <summary>
/// Maps the Scan page's real-time <see cref="ScanMascotMood"/> to the glow
/// color behind the robot mascot: neutral while idle, blue while a real scan
/// is running, green after a verified clean result, red after a verified
/// threat. Mirrors <see cref="ProtectionLevelToBrushConverter"/>'s pattern.
/// </summary>
public sealed class ScanMascotMoodToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var mood = value is ScanMascotMood m ? m : ScanMascotMood.Idle;
        var key = mood switch
        {
            ScanMascotMood.Scanning => "ElectricBlueBrush",
            ScanMascotMood.Clean => "AccentGreenBrush",
            ScanMascotMood.Alert => "DangerBrush",
            _ => "GlowBorderBrush"
        };

        return Application.Current.Resources.TryGetValue(key, out var brush) && brush is Brush b
            ? b
            : (Brush)Application.Current.Resources["GlowBorderBrush"];
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}
