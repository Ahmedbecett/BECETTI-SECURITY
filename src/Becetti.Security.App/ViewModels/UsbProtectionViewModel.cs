using System.Collections.ObjectModel;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// USB Protection page: the real list of currently connected removable
/// drives (System.IO.DriveInfo) and the real Windows AutoPlay/AutoRun policy
/// that blocks the classic autorun.inf USB-malware vector. Scanning a drive
/// hands its real path to Microsoft Defender — BECETTI SECURITY implements
/// no USB scanning engine of its own.
/// </summary>
public sealed class UsbProtectionViewModel : ViewModelBase
{
    private readonly IUsbProtectionService _usb;
    private readonly IDefenderService _defender;
    private readonly IEventLogService _events;
    private readonly SoundService _sound;

    private UsbDriveInfo? _selectedDrive;
    private string _autoRunText = "Not checked yet.";
    private bool _isAdministrator;

    public UsbProtectionViewModel(IUsbProtectionService usb, IDefenderService defender, IEventLogService events, SoundService sound)
    {
        _usb = usb;
        _defender = defender;
        _events = events;
        _sound = sound;
        RefreshCommand = new RelayCommand(LoadAsync);
        EnableAutoRunProtectionCommand = new RelayCommand(() => SetAutoRunProtectionAsync(true));
        DisableAutoRunProtectionCommand = new RelayCommand(() => SetAutoRunProtectionAsync(false));
    }

    public ObservableCollection<UsbDriveInfo> Drives { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand EnableAutoRunProtectionCommand { get; }
    public RelayCommand DisableAutoRunProtectionCommand { get; }

    public UsbDriveInfo? SelectedDrive { get => _selectedDrive; set => SetProperty(ref _selectedDrive, value); }
    public string AutoRunText { get => _autoRunText; set => SetProperty(ref _autoRunText, value); }
    public bool IsAdministrator { get => _isAdministrator; set => SetProperty(ref _isAdministrator, value); }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            IsAdministrator = _defender.IsElevated();
            var drivesResult = await _usb.GetConnectedDrivesAsync();
            Drives.Clear();
            if (drivesResult.Success && drivesResult.Value is not null)
            {
                foreach (var drive in drivesResult.Value)
                    Drives.Add(drive);
            }
            else
            {
                ErrorMessage = drivesResult.Message;
            }

            var autoRun = await _usb.GetAutoRunStatusAsync();
            if (autoRun.Success && autoRun.Value is not null)
            {
                AutoRunText = DescribeAutoRun(autoRun.Value);
            }
            else
            {
                AutoRunText = "Unknown";
                if (string.IsNullOrWhiteSpace(ErrorMessage))
                    ErrorMessage = autoRun.Message;
            }

            StatusMessage = Drives.Count == 0
                ? "No removable (USB) drives are currently connected."
                : $"{Drives.Count} removable drive(s) connected.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static string DescribeAutoRun(UsbAutoRunStatus status)
    {
        if (status.FullyProtected)
            return "Protected — Windows AutoPlay/AutoRun is blocked for removable drives and autorun.inf processing is disabled.";

        if (status.RemovableAutoRunBlocked == false || status.AutorunInfDisabled == false)
            return "Not fully protected — an explicit Windows policy value allows AutoRun on removable drives. Enable protection below.";

        if (status.RemovableAutoRunBlocked == true || status.AutorunInfDisabled == true)
            return "Partially configured — only one of the two AutoRun protections is explicitly set. Enable protection below to apply both.";

        return "Not explicitly configured by BECETTI SECURITY. Windows has hard-coded autorun.inf execution off for non-optical removable media since a 2011 security update, independent of this registry policy — enable below for an explicit, verifiable block.";
    }

    private async Task SetAutoRunProtectionAsync(bool enable)
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _usb.SetAutoRunProtectionAsync(enable);
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("usb.autorun.changed", result.Message, true);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("usb.autorun.failed", result.Message, false);
                _sound.Play(SoundCue.Warning);
            }
        }
        finally
        {
            // LoadAsync guards on its own IsBusy, so it must run after this method's
            // IsBusy is cleared or it would see IsBusy still true and silently no-op.
            IsBusy = false;
        }

        await LoadAsync();
    }
}
