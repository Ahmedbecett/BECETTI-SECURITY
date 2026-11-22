using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Game/Performance Mode: switches the real Windows active power plan to
/// "High performance" and turns on Windows' own Game Mode setting
/// (HKCU GameBar\AutoGameModeEnabled — the same value the Settings app's
/// Game Mode switch writes), so background throttling and some overlays
/// back off while the user plays or runs a demanding task. Both real
/// previous values are restored exactly when turned off. No performance
/// number (FPS, "% boost", etc.) is ever shown — Windows exposes none
/// honestly, so none is invented.
/// </summary>
public interface IGamePerformanceModeService
{
    Task<OperationResult<GamePerformanceStatus>> GetStatusAsync(CancellationToken ct = default);
    Task<OperationResult> EnableAsync(CancellationToken ct = default);
    Task<OperationResult> DisableAsync(CancellationToken ct = default);
}
