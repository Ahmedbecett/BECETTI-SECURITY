using System.Text.Json;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class PlatformSecurityServiceTests
{
    [Fact]
    public void ParseSnapshotJson_AllAvailable_ParsesEveryField()
    {
        const string json = "{" +
            "\"Tpm\":{\"Available\":true,\"Present\":true,\"Ready\":true,\"ManufacturerVersion\":\"1.2\"}," +
            "\"SecureBoot\":{\"Available\":true,\"Enabled\":true}," +
            "\"CredentialGuard\":{\"Available\":true,\"Running\":true}," +
            "\"BitLocker\":{\"Available\":true,\"MountPoint\":\"C:\",\"ProtectionStatus\":\"On\"}" +
            "}";

        var snapshot = PlatformSecurityService.ParseSnapshotJson(json);

        Assert.True(snapshot.Tpm.Available);
        Assert.True(snapshot.Tpm.Ready);
        Assert.Equal("1.2", snapshot.Tpm.ManufacturerVersion);
        Assert.True(snapshot.SecureBoot.Enabled);
        Assert.True(snapshot.CredentialGuard.Running);
        Assert.Equal("C:", snapshot.DiskEncryption.MountPoint);
        Assert.True(snapshot.DiskEncryption.IsProtected);
    }

    [Fact]
    public void ParseSnapshotJson_EmptyString_ReturnsUnavailableSnapshotRatherThanThrowing()
    {
        var snapshot = PlatformSecurityService.ParseSnapshotJson(string.Empty);

        Assert.False(snapshot.Tpm.Available);
        Assert.False(snapshot.SecureBoot.Available);
        Assert.False(snapshot.CredentialGuard.Available);
        Assert.False(snapshot.DiskEncryption.Available);
    }

    [Fact]
    public void ParseTpm_UnavailableWithError_SurfacesTheRealErrorRatherThanAGuess()
    {
        using var doc = JsonDocument.Parse("{\"Tpm\":{\"Available\":false,\"Error\":\"Get-Tpm is not recognized.\"}}");

        var tpm = PlatformSecurityService.ParseTpm(doc.RootElement);

        Assert.False(tpm.Available);
        Assert.Equal("Get-Tpm is not recognized.", tpm.RawError);
    }

    [Fact]
    public void ParseDiskEncryption_ProtectionOff_IsProtectedIsFalse()
    {
        using var doc = JsonDocument.Parse("{\"BitLocker\":{\"Available\":true,\"MountPoint\":\"C:\",\"ProtectionStatus\":\"Off\"}}");

        var disk = PlatformSecurityService.ParseDiskEncryption(doc.RootElement);

        Assert.True(disk.Available);
        Assert.False(disk.IsProtected);
    }

    [Fact]
    public void ParseSecureBoot_MissingSection_ReturnsUnavailable()
    {
        using var doc = JsonDocument.Parse("{}");

        var secureBoot = PlatformSecurityService.ParseSecureBoot(doc.RootElement);

        Assert.False(secureBoot.Available);
    }
}
