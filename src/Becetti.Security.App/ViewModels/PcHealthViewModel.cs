using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Smart PC Health page: live CPU/RAM/disk/service state from real Win32 and
/// .NET APIs (see PcHealthService). Nothing here is cached, estimated or
/// randomized — every refresh re-measures the device from scratch.
/// </summary>
public sealed class PcHealthViewModel : ViewModelBase
{
    private readonly IPcHealthService _pcHealth;

    private PcHealthSnapshot _snapshot = new();

    public PcHealthViewModel(IPcHealthService pcHealth)
    {
        _pcHealth = pcHealth;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

    public PcHealthSnapshot Snapshot
    {
        get => _snapshot;
        private set
        {
            if (SetProperty(ref _snapshot, value))
            {
                OnPropertyChanged(nameof(CpuText));
                OnPropertyChanged(nameof(MemoryText));
                OnPropertyChanged(nameof(Disks));
                OnPropertyChanged(nameof(Services));
                OnPropertyChanged(nameof(LastCheckedText));
            }
        }
    }

    public string CpuText => Snapshot.Performance.Available
        ? $"{Snapshot.Performance.CpuUsagePercent:0.0}%"
        : "Unavailable";

    public string MemoryText => Snapshot.Performance.Available
        ? $"{FormatBytes(Snapshot.Performance.TotalPhysicalMemoryBytes - Snapshot.Performance.AvailablePhysicalMemoryBytes)} of {FormatBytes(Snapshot.Performance.TotalPhysicalMemoryBytes)} used ({Snapshot.Performance.MemoryLoadPercent:0}%)"
        : "Unavailable";

    public IReadOnlyList<DiskHealthInfo> Disks => Snapshot.Disks;
    public IReadOnlyList<ServiceHealthInfo> Services => Snapshot.Services;

    public string LastCheckedText => $"Last checked: {Snapshot.CheckedAt:HH:mm:ss}";

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _pcHealth.GetSnapshotAsync();
            if (result.Success && result.Value is not null)
            {
                Snapshot = result.Value;
                StatusMessage = "PC health refreshed from live Windows APIs.";
            }
            else
            {
                ErrorMessage = result.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    internal static string FormatBytes(double bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        var value = Math.Max(bytes, 0);
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return $"{value:0.#} {units[unitIndex]}";
    }
}
