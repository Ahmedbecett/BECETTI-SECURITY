using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App.Views;

public sealed partial class BecettiAiPage : Page
{
    public BecettiAiViewModel ViewModel { get; }

    public BecettiAiPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<BecettiAiViewModel>();
    }
}
