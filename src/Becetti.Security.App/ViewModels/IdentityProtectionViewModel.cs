using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Identity Protection page: the real TPM, Secure Boot, Credential Guard and
/// BitLocker state from IPlatformSecurityService — the hardware/platform
/// features that protect credentials and data at rest.
/// </summary>
public sealed class IdentityProtectionViewModel : ViewModelBase
{
    private readonly IPlatformSecurityService _platform;

    private TpmStatus _tpm = new();
    private SecureBootStatus _secureBoot = new();
    private CredentialGuardStatus _credentialGuard = new();
    private DiskEncryptionStatus _diskEncryption = new();

    public IdentityProtectionViewModel(IPlatformSecurityService platform)
    {
        _platform = platform;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

    public TpmStatus Tpm { get => _tpm; set => SetProperty(ref _tpm, value); }
    public SecureBootStatus SecureBoot { get => _secureBoot; set => SetProperty(ref _secureBoot, value); }
    public CredentialGuardStatus CredentialGuard { get => _credentialGuard; set => SetProperty(ref _credentialGuard, value); }
    public DiskEncryptionStatus DiskEncryption { get => _diskEncryption; set => SetProperty(ref _diskEncryption, value); }

    public string TpmSummary => !Tpm.Available
        ? $"Unknown ({Tpm.RawError ?? "could not be verified"})"
        : Tpm.Ready ? "Present and ready" : "Present but not ready";

    public string SecureBootSummary => !SecureBoot.Available
        ? $"Unknown ({SecureBoot.RawError ?? "could not be verified"})"
        : SecureBoot.Enabled ? "Enabled" : "Disabled";

    public string CredentialGuardSummary => !CredentialGuard.Available
        ? $"Unknown ({CredentialGuard.RawError ?? "could not be verified"})"
        : CredentialGuard.Running ? "Running" : "Not running";

    public string DiskEncryptionSummary => !DiskEncryption.Available
        ? $"Unknown ({DiskEncryption.RawError ?? "could not be verified"})"
        : $"{DiskEncryption.MountPoint}: {(DiskEncryption.IsProtected ? "Protected" : "Not protected")}";

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _platform.GetSnapshotAsync();
            if (result.Success && result.Value is not null)
            {
                Tpm = result.Value.Tpm;
                SecureBoot = result.Value.SecureBoot;
                CredentialGuard = result.Value.CredentialGuard;
                DiskEncryption = result.Value.DiskEncryption;
                StatusMessage = "Platform security state read from Windows.";
            }
            else
            {
                ErrorMessage = result.Message;
            }

            OnPropertyChanged(nameof(TpmSummary));
            OnPropertyChanged(nameof(SecureBootSummary));
            OnPropertyChanged(nameof(CredentialGuardSummary));
            OnPropertyChanged(nameof(DiskEncryptionSummary));
        }
        finally
        {
            IsBusy = false;
        }
    }
}
