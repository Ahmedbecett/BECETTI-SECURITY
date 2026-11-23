using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App.Views;

public sealed partial class DomainHostingPage : Page
{
    public DomainHostingViewModel ViewModel { get; }

    public DomainHostingPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<DomainHostingViewModel>();
        DataContext = ViewModel;
    }
}
