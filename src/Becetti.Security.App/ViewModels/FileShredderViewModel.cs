using System.Collections.ObjectModel;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Secure File Shredder page: overwrites a chosen file's real bytes on disk
/// before deleting it, instead of a normal delete. The shredded file's name
/// and path are never written anywhere after the fact — the whole point of
/// this feature is that nothing recoverable is left behind, including in
/// BECETTI SECURITY's own history.
/// </summary>
public sealed class FileShredderViewModel : ViewModelBase
{
    private readonly IFileShredderService _shredder;

    private string _selectedFilePath = string.Empty;
    private int _passes = 3;

    public FileShredderViewModel(IFileShredderService shredder)
    {
        _shredder = shredder;
        ShredCommand = new RelayCommand(ShredAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(SelectedFilePath));
    }

    public RelayCommand ShredCommand { get; }

    /// <summary>This-session-only log of file names shredded (no path, no persistence).</summary>
    public ObservableCollection<string> SessionLog { get; } = new();

    public string SelectedFilePath
    {
        get => _selectedFilePath;
        set
        {
            if (SetProperty(ref _selectedFilePath, value))
                ShredCommand.RaiseCanExecuteChanged();
        }
    }

    public int Passes
    {
        get => _passes;
        set => SetProperty(ref _passes, value < 1 ? 1 : value);
    }

    private async Task ShredAsync()
    {
        if (IsBusy || string.IsNullOrWhiteSpace(SelectedFilePath))
            return;

        IsBusy = true;
        ClearMessages();
        var fileName = Path.GetFileName(SelectedFilePath);
        try
        {
            var result = await _shredder.ShredFileAsync(SelectedFilePath, Passes);
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            StatusMessage = result.Message;
            SessionLog.Insert(0, $"{DateTimeOffset.Now:HH:mm:ss} — \"{fileName}\" securely deleted.");
            SelectedFilePath = string.Empty;
        }
        finally
        {
            IsBusy = false;
        }
    }
}
