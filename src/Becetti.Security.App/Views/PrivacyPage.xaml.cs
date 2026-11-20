using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App.Views;

public sealed partial class PrivacyPage : Page
{
    public PrivacyViewModel ViewModel { get; }

    public PrivacyPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<PrivacyViewModel>();
    }
}
