using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises GamePerformanceModeService's pure parsing of powercfg.exe
/// output only. EnableAsync/DisableAsync actually switch the real Windows
/// power plan and a real registry value, so — matching this project's
/// established convention for services wrapping system commands (see
/// WifiSecurityServiceTests, DefenderParsingTests) — they are not exercised
/// here to avoid mutating the test machine's real system state.
/// </summary>
public sealed class GamePerformanceModeServiceTests
{
    [Fact]
    public void ParseActiveSchemeOutput_TypicalOutput_ExtractsGuidAndName()
    {
        const string output = "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)\r\n";

        var (guid, name) = GamePerformanceModeService.ParseActiveSchemeOutput(output);

        Assert.Equal("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", guid);
        Assert.Equal("High performance", name);
    }

    [Fact]
    public void ParseActiveSchemeOutput_BalancedScheme_ExtractsName()
    {
        const string output = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)\r\n";

        var (guid, name) = GamePerformanceModeService.ParseActiveSchemeOutput(output);

        Assert.Equal("381b4222-f694-41f0-9685-ff5bb260df2e", guid);
        Assert.Equal("Balanced", name);
    }

    [Fact]
    public void ParseActiveSchemeOutput_UnrecognizedOutput_ReturnsNulls()
    {
        var (guid, name) = GamePerformanceModeService.ParseActiveSchemeOutput("unexpected error text");

        Assert.Null(guid);
        Assert.Null(name);
    }
}
