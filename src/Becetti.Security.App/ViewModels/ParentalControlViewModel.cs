using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Parental Controls page: blocks chosen websites on this device by adding
/// real entries to the Windows hosts file — the same mechanism Windows uses
/// for every DNS lookup. No content-filtering service, no telemetry; the
/// blocklist lives only on this machine and requires Administrator to
/// change, exactly like changing the hosts file always has.
/// </summary>
public sealed class ParentalControlViewModel : ViewModelBase
{
    private readonly IParentalControlService _parental;
    private string _domainInput = string.Empty;

    public ParentalControlViewModel(IParentalControlService parental)
    {
        _parental = parental;
        BlockCommand = new RelayCommand(BlockAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(DomainInput));
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand BlockCommand { get; }
    public RelayCommand RefreshCommand { get; }

    public ObservableCollection<BlockedDomainInfo> BlockedDomains { get; } = new();

    public bool CanManageBlocklist => _parental.CanManageBlocklist;
    public bool CannotManageBlocklist => !CanManageBlocklist;

    public string DomainInput
    {
        get => _domainInput;
        set
        {
            if (SetProperty(ref _domainInput, value))
                BlockCommand.RaiseCanExecuteChanged();
        }
    }

    public async Task InitializeAsync()
    {
        await LoadAsync();
    }

    private async Task BlockAsync()
    {
        if (IsBusy || string.IsNullOrWhiteSpace(DomainInput))
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _parental.BlockDomainAsync(DomainInput.Trim());
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            StatusMessage = result.Message;
            DomainInput = string.Empty;
            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task UnblockAsync(string domain)
    {
        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _parental.UnblockDomainAsync(domain);
            StatusMessage = result.Message;
            if (!result.Success)
                ErrorMessage = result.Message;
            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadAsync()
    {
        OnPropertyChanged(nameof(CanManageBlocklist));
        OnPropertyChanged(nameof(CannotManageBlocklist));
        var result = await _parental.GetBlockedDomainsAsync();
        BlockedDomains.Clear();
        if (result.Success && result.Value is not null)
        {
            foreach (var domain in result.Value)
                BlockedDomains.Add(domain);
        }
        else if (!string.IsNullOrWhiteSpace(result.Message))
        {
            ErrorMessage = result.Message;
        }

        StatusMessage = $"{BlockedDomains.Count} blocked domain(s).";
    }
}
