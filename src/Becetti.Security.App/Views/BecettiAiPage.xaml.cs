using System.ComponentModel;
using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

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
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);

        // A caller (e.g. Smart Scan's "Ask BECETTI AI to explain this" button, or Threat
        // Management's equivalent) can pass a real report as the navigation parameter; it
        // only ever prefills the message box, the user must still tap Send themselves.
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

    private void OnPageLoaded(object sender, RoutedEventArgs e)
    {
        // The robot "walks in" from the edge once, every time this page opens —
        // purely a cinematic entrance, never implying anything about real state.
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
