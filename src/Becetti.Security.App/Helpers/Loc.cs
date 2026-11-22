using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App.Helpers;

/// <summary>
/// Attached property for instant, zero-restart UI localization in WinUI 3.
/// Applying <c>helpers:Loc.Uid="KeyName"</c> immediately populates the element's
/// localized properties from <see cref="LocalizationService"/> and automatically
/// updates them on the UI thread whenever the user switches language.
/// </summary>
public static class Loc
{
    public static readonly DependencyProperty UidProperty =
        DependencyProperty.RegisterAttached(
            "Uid",
            typeof(string),
            typeof(Loc),
            new PropertyMetadata(null, OnUidChanged));

    private static readonly DependencyProperty HookedHandlerProperty =
        DependencyProperty.RegisterAttached(
            "HookedHandler",
            typeof(EventHandler),
            typeof(Loc),
            new PropertyMetadata(null));

    private static readonly DependencyProperty LifecycleWiredProperty =
        DependencyProperty.RegisterAttached(
            "LifecycleWired",
            typeof(bool),
            typeof(Loc),
            new PropertyMetadata(false));

    public static string? GetUid(DependencyObject obj) => (string?)obj.GetValue(UidProperty);
    public static void SetUid(DependencyObject obj, string? value) => obj.SetValue(UidProperty, value);

    private static void OnUidChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var uid = e.NewValue as string;
        if (string.IsNullOrWhiteSpace(uid))
            return;

        Apply(d, uid);

        if (d is FrameworkElement fe && !(bool)fe.GetValue(LifecycleWiredProperty))
        {
            fe.SetValue(LifecycleWiredProperty, true);
            fe.Loaded += OnElementLoaded;
            fe.Unloaded += OnElementUnloaded;

            if (fe.IsLoaded)
                AttachLanguageListener(fe);
        }
    }

    private static void OnElementLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe)
            return;

        Apply(fe, GetUid(fe));
        AttachLanguageListener(fe);
    }

    private static void OnElementUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe)
            return;

        DetachLanguageListener(fe);
    }

    private static void AttachLanguageListener(FrameworkElement fe)
    {
        var loc = TryGetLocalization();
        if (loc is null)
            return;

        if (fe.GetValue(HookedHandlerProperty) is EventHandler)
            return;

        EventHandler handler = (_, _) =>
        {
            var dq = fe.DispatcherQueue;
            if (dq is not null)
                dq.TryEnqueue(() => Apply(fe, GetUid(fe)));
            else
                Apply(fe, GetUid(fe));
        };

        fe.SetValue(HookedHandlerProperty, handler);
        loc.LanguageChanged += handler;
    }

    private static void DetachLanguageListener(FrameworkElement fe)
    {
        var loc = TryGetLocalization();
        if (fe.GetValue(HookedHandlerProperty) is EventHandler handler)
        {
            if (loc is not null)
                loc.LanguageChanged -= handler;
            fe.SetValue(HookedHandlerProperty, null);
        }
    }

    public static void Apply(DependencyObject element, string? uid)
    {
        if (string.IsNullOrWhiteSpace(uid))
            return;

        var loc = TryGetLocalization();
        if (loc is null)
            return;

        switch (element)
        {
            case TextBlock tb:
                if (loc.TryGet(uid, "Text") is { } text)
                    tb.Text = text;
                break;

            case ToggleSwitch ts:
                if (loc.TryGet(uid, "Header") is { } tsHeader)
                    ts.Header = tsHeader;
                break;

            case TextBox box:
                if (loc.TryGet(uid, "Header") is { } boxHeader)
                    box.Header = boxHeader;
                if (loc.TryGet(uid, "PlaceholderText") is { } boxPlaceholder)
                    box.PlaceholderText = boxPlaceholder;
                break;

            case PasswordBox pbox:
                if (loc.TryGet(uid, "Header") is { } pboxHeader)
                    pbox.Header = pboxHeader;
                if (loc.TryGet(uid, "PlaceholderText") is { } pboxPlaceholder)
                    pbox.PlaceholderText = pboxPlaceholder;
                break;

            case InfoBar bar:
                if (loc.TryGet(uid, "Title") is { } barTitle)
                    bar.Title = barTitle;
                if (loc.TryGet(uid, "Message") is { } barMsg)
                    bar.Message = barMsg;
                break;

            case ContentControl cc:
                if (loc.TryGet(uid, "Content") is { } content)
                    cc.Content = content;
                break;
        }

        if (loc.TryGet(uid, "ToolTip") is { } tip)
            ToolTipService.SetToolTip(element, tip);
    }

    private static LocalizationService? TryGetLocalization()
    {
        try
        {
            return App.Services?.GetService<LocalizationService>();
        }
        catch
        {
            return null;
        }
    }
}
