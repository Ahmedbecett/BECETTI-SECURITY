using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Secure Vault page: local AES-256-GCM encrypted storage for files the
/// user explicitly adds. The key is protected with Windows DPAPI, the same
/// mechanism already used for cloud tokens. This is entirely local — no
/// network call is ever made by this feature.
/// </summary>
public sealed class SecureVaultViewModel : ViewModelBase
{
    private readonly ISecureVaultService _vault;

    private string _pendingFilePath = string.Empty;
    private bool _shredOriginalAfterAdd = true;
    private VaultItemInfo? _selectedItem;

    public SecureVaultViewModel(ISecureVaultService vault)
    {
        _vault = vault;
        InitializeVaultCommand = new RelayCommand(InitializeVaultAsync, () => !IsBusy && !IsInitialized);
        AddFileCommand = new RelayCommand(AddFileAsync, () => !IsBusy && IsInitialized && !string.IsNullOrWhiteSpace(PendingFilePath));
        RefreshCommand = new RelayCommand(LoadAsync);
        DeleteSelectedCommand = new RelayCommand(DeleteSelectedAsync, () => !IsBusy && SelectedItem is not null);
    }

    public RelayCommand InitializeVaultCommand { get; }
    public RelayCommand AddFileCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand DeleteSelectedCommand { get; }

    public ObservableCollection<VaultItemInfo> Items { get; } = new();

    public bool IsInitialized => _vault.IsInitialized;

    public string PendingFilePath
    {
        get => _pendingFilePath;
        set
        {
            if (SetProperty(ref _pendingFilePath, value))
                AddFileCommand.RaiseCanExecuteChanged();
        }
    }

    public bool ShredOriginalAfterAdd
    {
        get => _shredOriginalAfterAdd;
        set => SetProperty(ref _shredOriginalAfterAdd, value);
    }

    public VaultItemInfo? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetProperty(ref _selectedItem, value))
                DeleteSelectedCommand.RaiseCanExecuteChanged();
        }
    }

    public bool HasSelection => SelectedItem is not null;

    public async Task InitializeAsync()
    {
        await LoadAsync();
    }

    private async Task InitializeVaultAsync()
    {
        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _vault.InitializeAsync();
            StatusMessage = result.Success ? result.Message : string.Empty;
            if (!result.Success)
                ErrorMessage = result.Message;

            OnPropertyChanged(nameof(IsInitialized));
            InitializeVaultCommand.RaiseCanExecuteChanged();
            AddFileCommand.RaiseCanExecuteChanged();
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Called by the page after the file picker returns, so a real extraction destination is used.</summary>
    public async Task AddFileAsync()
    {
        if (IsBusy || string.IsNullOrWhiteSpace(PendingFilePath))
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _vault.AddFileAsync(PendingFilePath, ShredOriginalAfterAdd);
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            StatusMessage = result.Message;
            PendingFilePath = string.Empty;
            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task<OperationResult> ExtractAsync(Guid itemId, string destinationPath)
    {
        return await _vault.ExtractFileAsync(itemId, destinationPath);
    }

    private async Task DeleteSelectedAsync()
    {
        if (SelectedItem is null)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _vault.DeleteItemAsync(SelectedItem.Id);
            StatusMessage = result.Message;
            if (!result.Success)
                ErrorMessage = result.Message;

            SelectedItem = null;
            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadAsync()
    {
        OnPropertyChanged(nameof(IsInitialized));
        var items = await _vault.ListItemsAsync();
        Items.Clear();
        foreach (var item in items.OrderByDescending(i => i.AddedUtc))
            Items.Add(item);

        StatusMessage = IsInitialized
            ? $"{Items.Count} file(s) in the vault."
            : "The vault has not been created yet.";
    }
}
