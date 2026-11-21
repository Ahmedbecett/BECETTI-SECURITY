using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class ProtectionStatusEvaluatorTests
{
    [Fact]
    public void Null_Status_IsUnknown()
    {
        Assert.Equal(ProtectionLevel.Unknown, ProtectionStatusEvaluator.Evaluate(null));
    }

    [Fact]
    public void Unavailable_Status_IsUnknown()
    {
        var status = new DefenderStatus { Available = false };
        Assert.Equal(ProtectionLevel.Unknown, ProtectionStatusEvaluator.Evaluate(status));
    }

    [Fact]
    public void AntivirusDisabled_IsDanger()
    {
        var status = new DefenderStatus { Available = true, AntivirusEnabled = false };
        Assert.Equal(ProtectionLevel.Danger, ProtectionStatusEvaluator.Evaluate(status));
    }

    [Fact]
    public void AntivirusEnabled_RealTimeOff_IsWarning()
    {
        var status = new DefenderStatus { Available = true, AntivirusEnabled = true, RealTimeProtectionEnabled = false };
        Assert.Equal(ProtectionLevel.Warning, ProtectionStatusEvaluator.Evaluate(status));
    }

    [Fact]
    public void ManagedByAnotherAntivirus_IsWarning_EvenWithRealTimeOn()
    {
        var status = new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = true,
            RealTimeProtectionEnabled = true,
            RunningMode = "Passive Mode"
        };
        Assert.Equal(ProtectionLevel.Warning, ProtectionStatusEvaluator.Evaluate(status));
    }

    [Fact]
    public void AntivirusEnabled_RealTimeOn_NormalMode_IsProtected()
    {
        var status = new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = true,
            RealTimeProtectionEnabled = true,
            RunningMode = "Normal"
        };
        Assert.Equal(ProtectionLevel.Protected, ProtectionStatusEvaluator.Evaluate(status));
    }
}
