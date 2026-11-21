using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App.Views;

public sealed partial class ContactPage : Page
{
    public ContactViewModel ViewModel { get; }

    public ContactPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ContactViewModel>();
    }
}
