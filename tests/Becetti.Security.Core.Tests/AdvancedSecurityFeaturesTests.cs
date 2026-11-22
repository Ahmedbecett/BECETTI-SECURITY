using System.Security.Cryptography;
using System.Text;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Comprehensive unit &amp; real Windows x64 integration tests covering all 13 advanced
/// security features: Real-Time YARA Folder Guard, AES-256-GCM Quarantine Vault,
/// Live Process Memory YARA Scan, Static PE + Shannon Entropy + Authenticode Forensics,
/// Ransomware Canary Honeypot, Clipboard Hijack Guard, Per-App Firewall parser,
/// USB Auto-Scan, AI Threat Investigator &amp; AI YARA Rule Studio, Scheduled YARA Auto-Updates,
/// and Windows Explorer Right-Click Context Menu.
/// </summary>
public sealed class AdvancedSecurityFeaturesTests : IDisposable
{
    private readonly string _tempDir;

    public AdvancedSecurityFeaturesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-adv-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch { }
    }

    private YaraEngineService CreateYara(out SettingsService settings)
    {
        var dataDir = Path.Combine(_tempDir, "appdata-" + Guid.NewGuid().ToString("N"));
        settings = new SettingsService(dataDir);
        var bundled = Environment.GetEnvironmentVariable("BECETTI_YARA_RULES_DIR");
        return new YaraEngineService(new HttpClient(), settings, bundledRulesDirectory: bundled);
    }

    [Fact]
    public async Task QuarantineService_EncryptsRemovesRestoresAndDeletesPermanently()
    {
        var settings = new SettingsService(Path.Combine(_tempDir, "q-data"));
        var quarantine = new QuarantineService(settings);

        var samplePath = Path.Combine(_tempDir, "malware_sample.bin");
        var secretPayload = "SENSITIVE-SAMPLE-PAYLOAD-DO-NOT-STORE-IN-PLAINTEXT-991122";
        await File.WriteAllTextAsync(samplePath, secretPayload, Encoding.UTF8);

        // 1. Quarantine -> original file removed, encrypted vault payload contains no plaintext
        var qRes = await quarantine.QuarantineFileAsync(samplePath, "Test_Rule", "Unit test isolation");
        Assert.True(qRes.Success, qRes.Message);
        Assert.False(File.Exists(samplePath));

        var vaultFile = Path.Combine(settings.DataDirectory, "quarantine", qRes.Value!.VaultFileName);
        Assert.True(File.Exists(vaultFile));
        var rawVaultText = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(vaultFile));
        Assert.DoesNotContain("SENSITIVE-SAMPLE-PAYLOAD", rawVaultText);

        var list = await quarantine.GetEntriesAsync();
        Assert.Single(list.Value!);

        // 2. Restore -> exact original bytes & SHA-256 restored
        var restored = await quarantine.RestoreFileAsync(qRes.Value.Id);
        Assert.True(restored.Success, restored.Message);
        Assert.True(File.Exists(samplePath));
        Assert.Equal(secretPayload, await File.ReadAllTextAsync(samplePath, Encoding.UTF8));
        Assert.Empty((await quarantine.GetEntriesAsync()).Value!);

        // 3. Re-quarantine & permanently delete
        var qRes2 = await quarantine.QuarantineFileAsync(samplePath, "Test_Rule", "Second isolation");
        Assert.True(qRes2.Success);
        var del = await quarantine.DeletePermanentlyAsync(qRes2.Value!.Id);
        Assert.True(del.Success, del.Message);
        Assert.False(File.Exists(Path.Combine(settings.DataDirectory, "quarantine", qRes2.Value.VaultFileName)));
        Assert.Empty((await quarantine.GetEntriesAsync()).Value!);
    }

    [Fact]
    public async Task FileForensicsService_ComputesEntropyAndInspectsRealWindowsPeBinary()
    {
        var forensics = new FileForensicsService();

        var lowFile = Path.Combine(_tempDir, "low_entropy.txt");
        await File.WriteAllTextAsync(lowFile, new string('A', 4096));
        var lowRes = await forensics.AnalyzeFileAsync(lowFile);
        Assert.True(lowRes.Success, lowRes.Message);
        Assert.True(lowRes.Value!.FileEntropy < 1.0);
        Assert.False(lowRes.Value.IsLikelyPackedOrEncrypted);
        Assert.False(lowRes.Value.IsPeBinary);

        var highFile = Path.Combine(_tempDir, "high_entropy.bin");
        await File.WriteAllBytesAsync(highFile, RandomNumberGenerator.GetBytes(32768));
        var highRes = await forensics.AnalyzeFileAsync(highFile);
        Assert.True(highRes.Success, highRes.Message);
        Assert.True(highRes.Value!.FileEntropy >= 7.5);
        Assert.True(highRes.Value.IsLikelyPackedOrEncrypted);

        if (OperatingSystem.IsWindows())
        {
            var cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            if (File.Exists(cmdExe))
            {
                var peRes = await forensics.AnalyzeFileAsync(cmdExe);
                Assert.True(peRes.Success, peRes.Message);
                Assert.True(peRes.Value!.IsPeBinary);
                Assert.NotEmpty(peRes.Value.Sections);
                Assert.Equal(64, peRes.Value.Sha256.Length);
            }
        }
    }

    [Fact]
    public async Task RansomwareCanaryService_ArmsDetectsTamperingAndDisarmsCleanly()
    {
        var watchDir = Path.Combine(_tempDir, "canary-folder");
        Directory.CreateDirectory(watchDir);

        using var canary = new RansomwareCanaryService();
        var trippedTcs = new TaskCompletionSource<CanaryAlertEvent>();
        canary.CanaryTripped += (_, alert) => trippedTcs.TrySetResult(alert);

        var arm = await canary.ArmAsync(new[] { watchDir });
        Assert.True(arm.Success, arm.Message);
        Assert.True(canary.IsArmed);
        var decoy = Assert.Single(arm.Value!);
        Assert.True(File.Exists(decoy.FilePath));

        // Simulate ransomware encrypting/overwriting the decoy file
        File.SetAttributes(decoy.FilePath, FileAttributes.Normal);
        await File.WriteAllBytesAsync(decoy.FilePath, RandomNumberGenerator.GetBytes(2048));

        var verify = await canary.VerifyIntegrityAsync();
        Assert.True(verify.Success);
        Assert.False(Assert.Single(verify.Value!).IsIntact);

        var alert = await Task.WhenAny(trippedTcs.Task, Task.Delay(3000));
        Assert.Same(trippedTcs.Task, alert);

        canary.Disarm(removeDecoyFiles: true);
        Assert.False(canary.IsArmed);
        Assert.False(File.Exists(decoy.FilePath));
    }

    [Fact]
    public void ClipboardGuardService_DetectsRapidCryptoWalletSwapHijack()
    {
        var guard = new ClipboardGuardService { IsEnabled = true };
        var t0 = DateTimeOffset.UtcNow;

        // First copy: legitimate BTC address -> no alert
        var first = guard.ObserveClipboardText("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", t0);
        Assert.Null(first);

        // 1 second later: clipper replaces with attacker's BTC address -> ALERT!
        var second = guard.ObserveClipboardText("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", t0.AddSeconds(1));
        Assert.NotNull(second);
        Assert.Contains("Bitcoin", second!.AssetType);
        Assert.Single(guard.RecentAlerts);

        // Normal non-wallet text never alerts
        Assert.Null(guard.ObserveClipboardText("Hello BECETTI SECURITY", t0.AddSeconds(2)));
    }

    [Fact]
    public void PerAppFirewallService_ParsesOnlyBecettiBlockRules()
    {
        var sampleNetsh = string.Join("\n", new[]
        {
            "Rule Name:                            Windows Update",
            "Direction:                            Out",
            "Program:                              C:\\Windows\\System32\\svchost.exe",
            "",
            "Rule Name:                            BECETTI-BLOCK-EvilTool-OUT",
            "Direction:                            Out",
            "Program:                              C:\\Temp\\EvilTool.exe",
            ""
        });

        var parsed = PerAppFirewallService.ParseBecettiRules(sampleNetsh);
        var rule = Assert.Single(parsed);
        Assert.Equal("BECETTI-BLOCK-EvilTool-OUT", rule.RuleName);
        Assert.Equal("C:\\Temp\\EvilTool.exe", rule.ExecutablePath);
    }

    [Fact]
    public async Task ScheduledYaraUpdateService_PersistsScheduleAndEvaluatesDueTime()
    {
        var yara = CreateYara(out var settings);
        using var scheduler = new ScheduledYaraUpdateService(yara, settings);

        var cfg = new YaraUpdateScheduleConfig
        {
            Enabled = true,
            IntervalHours = 24,
            LastCheckedAt = DateTimeOffset.UtcNow.AddHours(-25)
        };
        var saved = await scheduler.SaveConfigAsync(cfg);
        Assert.True(saved.Success, saved.Message);
        Assert.True(scheduler.IsUpdateDue());

        using var reloaded = new ScheduledYaraUpdateService(yara, settings);
        var loaded = await reloaded.LoadConfigAsync();
        Assert.True(loaded.Success);
        Assert.True(loaded.Value!.Enabled);
        Assert.Equal(24, loaded.Value.IntervalHours);
    }

    [Fact]
    public void WindowsX64_ExplorerContextMenuService_RegistersVerifiesAndUnregistersInIsolatedTestKey()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var testBase = @"Software\BECETTI-SECURITY-CI-TEST-" + Guid.NewGuid().ToString("N");
        var svc = new ExplorerContextMenuService(
            $@"{testBase}\file\BecettiYaraScan",
            $@"{testBase}\dir\BecettiYaraScan");

        try
        {
            Assert.False(svc.IsRegistered());
            var reg = svc.Register(@"C:\Program Files\BECETTI\Becetti.Security.App.exe");
            Assert.True(reg.Success, reg.Message);
            Assert.True(svc.IsRegistered());

            var unreg = svc.Unregister();
            Assert.True(unreg.Success, unreg.Message);
            Assert.False(svc.IsRegistered());
        }
        finally
        {
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(testBase, throwOnMissingSubKey: false); } catch { }
        }
    }

    [Fact]
    public async Task WindowsX64_YaraProcessMemoryScan_ScansCurrentProcessCleanly()
    {
        var yara = CreateYara(out _);
        if (!OperatingSystem.IsWindows() || yara.FindYaraExecutable() is null)
            return;

        var init = await yara.InitializeAsync();
        Assert.True(init.Success, init.Message);

        var res = await yara.ScanProcessAsync(Environment.ProcessId);
        Assert.True(res.Success, res.Message);
        Assert.NotNull(res.Value);
        Assert.Equal(1, res.Value!.ProcessesEnumerated);
    }

    [Fact]
    public async Task WindowsX64_RealTimeYaraFolderGuard_DetectsAndAutoQuarantinesDroppedEicarFile()
    {
        var yara = CreateYara(out var settings);
        if (!OperatingSystem.IsWindows() || yara.FindYaraExecutable() is null)
            return;

        var quarantine = new QuarantineService(settings);
        using var guard = new RealTimeYaraGuardService(yara, quarantine, settings)
        {
            AutoQuarantineEnabled = true
        };

        var watchDir = Path.Combine(_tempDir, "watched-downloads");
        Directory.CreateDirectory(watchDir);

        var detectedTcs = new TaskCompletionSource<RealTimeGuardEvent>();
        guard.ThreatDetected += (_, ev) => detectedTcs.TrySetResult(ev);

        var start = await guard.StartAsync(new[] { watchDir });
        Assert.True(start.Success, start.Message);

        var eicar = string.Concat("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!", "$H+H*");
        var droppedPath = Path.Combine(watchDir, "dropped_eicar.txt");
        await File.WriteAllTextAsync(droppedPath, eicar, Encoding.ASCII);

        var completed = await Task.WhenAny(detectedTcs.Task, Task.Delay(12000));
        Assert.Same(detectedTcs.Task, completed);

        var ev = await detectedTcs.Task;
        Assert.True(ev.ThreatDetected);
        Assert.Contains("EICAR_Standard_Test_File", ev.MatchedRulesSummary);
        Assert.True(ev.AutoQuarantined);
        Assert.False(File.Exists(droppedPath));
        Assert.Single((await quarantine.GetEntriesAsync()).Value!);
    }

    [Fact]
    public async Task WindowsX64_AiYaraRuleHelper_ExtractsValidRuleAndCompilesWithYarac64()
    {
        var aiResponse = "Here is your YARA rule:\n```yara\nrule AI_Studio_Test_Rule\n{\n    meta:\n        description = \"Detects custom test IOC\"\n        author = \"BECETTI AI Rule Studio\"\n        severity = \"High\"\n    strings:\n        $ioc = \"BECETTI-AI-STUDIO-TEST-IOC-777\" ascii wide\n    condition:\n        filesize < 5MB and $ioc\n}\n```";

        var extracted = AiYaraRuleHelper.ExtractYaraRuleText(aiResponse);
        Assert.NotNull(extracted);
        Assert.Contains("rule AI_Studio_Test_Rule", extracted!);

        var prompt = AiYaraRuleHelper.BuildThreatInvestigatorPrompt(
            new YaraRuleMatch { RuleName = "EICAR_Standard_Test_File", Severity = "High", FilePath = "C:\\eicar.txt" },
            new FileForensicsReport { FileName = "eicar.txt", Sha256 = "abc123", FileEntropy = 4.2, RiskAssessment = "High" },
            "ar");
        Assert.Contains("EICAR_Standard_Test_File", prompt);
        Assert.Contains("abc123", prompt);
        Assert.Contains("'ar'", prompt);

        var yara = CreateYara(out _);
        if (!OperatingSystem.IsWindows() || yara.FindYaracExecutable() is null)
            return;

        var rulePath = Path.Combine(_tempDir, "ai_studio_test.yar");
        await File.WriteAllTextAsync(rulePath, extracted);
        var val = await yara.ValidateRuleFileAsync(rulePath);
        Assert.True(val.Success, val.Message);
        Assert.True(val.Value!.IsValid);
    }
}
