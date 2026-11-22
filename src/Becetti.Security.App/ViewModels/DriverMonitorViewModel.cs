using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Driver Monitor: the real installed-driver inventory from WMI
/// (Win32_PnPSignedDriver), the same source Device Manager itself reads.
/// Read-only — BECETTI SECURITY has no driver "known issue" database of its
/// own, so it only flags unsigned drivers (a real, verifiable fact) and
/// points to Windows Update / the manufacturer for updates.
/// </summary>
public sealed class DriverMonitorViewModel : ViewModelBase
{
    private readonly IDriverMonitorService _drivers;

    public DriverMonitorViewModel(IDriverMonitorService drivers)
    {
        _drivers = drivers;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public ObservableCollection<DriverInfo> Drivers { get; } = new();

    public RelayCommand RefreshCommand { get; }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _drivers.GetDriversAsync();
            Drivers.Clear();

            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                StatusMessage = "Driver list unavailable.";
                return;
            }

            foreach (var driver in result.Value)
                Drivers.Add(driver);

            var unsigned = Drivers.Count(d => !d.IsSigned);
            StatusMessage = unsigned == 0
                ? $"{Drivers.Count} driver(s) read from Windows — all are digitally signed."
                : $"{Drivers.Count} driver(s) read from Windows — {unsigned} unsigned driver(s) found. Check the manufacturer's official site for a signed update.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
