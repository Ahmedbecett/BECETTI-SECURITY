using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class ThreatsPage : Page
{
    public ThreatsViewModel ViewModel { get; }

    public ThreatsPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ThreatsViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    /// <summary>
    /// Sends the real selected threat to BECETTI AI as a prefilled message — the user
    /// still has to review it and tap Send; nothing is transmitted automatically here.
    /// </summary>
    private void AskAiAboutThreat_Click(object sender, RoutedEventArgs e)
    {
        var prompt = ViewModel.BuildAiExplainPrompt();
        if (prompt is null)
        {
            ViewModel.ErrorMessage = "Select a threat first.";
            return;
        }

        App.MainWindow?.NavigateTo("Ai", prompt);
    }
}
