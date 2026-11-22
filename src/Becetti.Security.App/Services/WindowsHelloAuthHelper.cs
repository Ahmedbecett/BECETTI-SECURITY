using Becetti.Security.Core.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Security.Credentials.UI;

namespace Becetti.Security.App.Services;

/// <summary>
/// Real Anti-Tamper App Lock Authenticator:
/// attempts native Windows Hello (biometric / Windows PIN via UserConsentVerifier) first,
/// with automatic fallback to BECETTI SECURITY's PBKDF2-SHA256 local Security PIN dialog.
/// </summary>
public static class WindowsHelloAuthHelper
{
    public static async Task<bool> IsWindowsHelloAvailableAsync()
    {
        try
        {
            var avail = await UserConsentVerifier.CheckAvailabilityAsync();
            return avail == UserConsentVerifierAvailability.Available;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<bool> VerifyAccessAsync(XamlRoot? xamlRoot, IAppLockService appLock, string reason)
    {
        if (!appLock.IsEnabled || appLock.IsSessionUnlocked)
            return true;

        // 1. Try native Windows Hello first if available
        try
        {
            var avail = await UserConsentVerifier.CheckAvailabilityAsync();
            if (avail == UserConsentVerifierAvailability.Available)
            {
                var result = await UserConsentVerifier.RequestVerificationAsync(reason);
                if (result == UserConsentVerificationResult.Verified)
                {
                    appLock.MarkSessionUnlocked();
                    return true;
                }
                if (!appLock.HasPinConfigured)
                    return false;
            }
        }
        catch
        {
            // Fall back to local PIN dialog
        }

        // 2. Fallback to PBKDF2-SHA256 local Security PIN dialog
        if (xamlRoot is null || !appLock.HasPinConfigured)
            return !appLock.HasPinConfigured;

        var pinBox = new PasswordBox
        {
            PlaceholderText = "Enter BECETTI SECURITY PIN",
            MaxLength = 32
        };
        var errorText = new TextBlock
        {
            Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.IndianRed),
            Visibility = Visibility.Collapsed,
            Text = "Incorrect PIN. Please try again."
        };
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(new TextBlock { Text = reason, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(pinBox);
        panel.Children.Add(errorText);

        var dialog = new ContentDialog
        {
            XamlRoot = xamlRoot,
            Title = "Anti-Tamper Verification",
            Content = panel,
            PrimaryButtonText = "Unlock",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };

        for (int attempt = 0; attempt < 3; attempt++)
        {
            var choice = await dialog.ShowAsync();
            if (choice != ContentDialogResult.Primary)
                return false;

            if (appLock.VerifyPin(pinBox.Password))
                return true;

            pinBox.Password = string.Empty;
            errorText.Visibility = Visibility.Visible;
        }

        return false;
    }
}
