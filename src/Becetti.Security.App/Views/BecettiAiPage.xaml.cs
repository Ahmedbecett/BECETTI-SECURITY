using System.Collections.Specialized;
using System.ComponentModel;
using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Windows.System;

namespace Becetti.Security.App.Views;

public sealed partial class BecettiAiPage : Page
{
    public BecettiAiViewModel ViewModel { get; }

    public BecettiAiPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<BecettiAiViewModel>();

        Loaded += OnPageLoaded;
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        ViewModel.Messages.CollectionChanged += OnMessagesChanged;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);

        if (e.Parameter is string seedText && !string.IsNullOrWhiteSpace(seedText))
            ViewModel.SeedInput(seedText);

        var localization = App.Services.GetRequiredService<LocalizationService>();
        var (welcomeText, languageTag) = localization.Current switch
        {
            AppLanguage.Arabic => ("مرحباً، أنت بأمان.", "ar-SA"),
            AppLanguage.French => ("Bienvenue, vous êtes en sécurité.", "fr-FR"),
            _ => ("Welcome, you are safe.", "en-US")
        };

        await ViewModel.PlayWelcomeIfEmptyAsync(welcomeText, languageTag);
    }

    private void InputBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter && ViewModel.SendCommand.CanExecute(null))
        {
            e.Handled = true;
            ViewModel.SendCommand.Execute(null);
        }
    }

    private void OnMessagesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        DispatcherQueue?.TryEnqueue(() =>
        {
            ChatScroller.UpdateLayout();
            ChatScroller.ChangeView(null, ChatScroller.ScrollableHeight, null, disableAnimation: false);
        });
    }

    private void OnPageLoaded(object sender, RoutedEventArgs e)
    {
        if (Resources.TryGetValue("RobotEntranceStoryboard", out var entrance) && entrance is Storyboard storyboard)
            storyboard.Begin();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(BecettiAiViewModel.IsSpeaking))
            return;

        if (Resources.TryGetValue("RobotTalkingStoryboard", out var talking) && talking is Storyboard storyboard)
        {
            if (ViewModel.IsSpeaking)
                storyboard.Begin();
            else
                storyboard.Stop();
        }
    }
}
