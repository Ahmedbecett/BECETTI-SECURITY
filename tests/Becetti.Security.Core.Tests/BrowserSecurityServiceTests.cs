using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class BrowserSecurityServiceTests
{
    private sealed class FakeSoftwareManagerService : ISoftwareManagerService
    {
        private readonly IReadOnlyList<InstalledAppInfo> _apps;

        public FakeSoftwareManagerService(IReadOnlyList<InstalledAppInfo> apps) => _apps = apps;

        public Task<OperationResult<IReadOnlyList<InstalledAppInfo>>> GetInstalledAppsAsync() =>
            Task.FromResult(OperationResult<IReadOnlyList<InstalledAppInfo>>.Ok(_apps));

        public OperationResult LaunchUninstaller(InstalledAppInfo app) => OperationResult.Ok();
    }

    [Fact]
    public async Task GetInstalledBrowsersAsync_FiltersNonBrowserAppsOut()
    {
        var apps = new List<InstalledAppInfo>
        {
            new() { Name = "Google Chrome", Version = "120.0", Publisher = "Google LLC" },
            new() { Name = "7-Zip 23.01", Version = "23.01", Publisher = "Igor Pavlov" },
            new() { Name = "Mozilla Firefox", Version = "121.0", Publisher = "Mozilla" },
        };

        var service = new BrowserSecurityService(new FakeSoftwareManagerService(apps));

        var result = await service.GetInstalledBrowsersAsync();

        Assert.True(result.Success);
        Assert.Contains(result.Value!, b => b.Name == "Google Chrome");
        Assert.Contains(result.Value!, b => b.Name == "Mozilla Firefox");
        Assert.DoesNotContain(result.Value!, b => b.Name.Contains("7-Zip"));
    }

    [Fact]
    public async Task GetInstalledBrowsersAsync_SoftwareManagerFails_PropagatesTheRealFailure()
    {
        var service = new BrowserSecurityService(new FailingSoftwareManagerService());

        var result = await service.GetInstalledBrowsersAsync();

        Assert.False(result.Success);
    }

    private sealed class FailingSoftwareManagerService : ISoftwareManagerService
    {
        public Task<OperationResult<IReadOnlyList<InstalledAppInfo>>> GetInstalledAppsAsync() =>
            Task.FromResult(OperationResult<IReadOnlyList<InstalledAppInfo>>.Fail("Registry unavailable.", "REGISTRY_ERROR"));

        public OperationResult LaunchUninstaller(InstalledAppInfo app) => OperationResult.Ok();
    }
}
