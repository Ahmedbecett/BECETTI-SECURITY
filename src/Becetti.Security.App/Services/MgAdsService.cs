using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Windows.Foundation;
using WinRT.Interop;

namespace Becetti.Security.App.Services;

/// <summary>
/// Bridges the WinUI 3 shell to the out-of-process MG Ads host
/// (src/Becetti.Security.MgAdsHost). The MG Ads C# SDK is a .NET Framework
/// 4.7.2 WinForms/WebView2 SDK and cannot be loaded into this .NET 8 process,
/// so the SDK runs in its own host and paints into owned windows that are
/// positioned over the reserved 728x90 banner surface and over the full
/// client area for the 1920x1080 full-screen unit.
///
/// Failure is always non-fatal: if the host or SDK cannot start, BECETTI
/// SECURITY keeps every security feature and simply shows its placeholder.
/// </summary>
public sealed class MgAdsService
{
    private readonly Window _window;
    private readonly FrameworkElement _bannerSurface;
    private readonly DispatcherQueue _queue;

    private NamedPipeServerStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private Process? _process;
    private readonly object _writeLock = new();

    private string? _bannerUnitId;
    private string? _fullScreenUnitId;
    private IntPtr _hwnd;
    private volatile bool _ready;
    private volatile bool _splashPending;
    private bool _stopped;

    public bool IsReady => _ready;

    /// <summary>Diagnostics for the About/diagnostic log; never user-visible.</summary>
    public event Action<string>? Log;

    public MgAdsService(Window window, FrameworkElement bannerSurface)
    {
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _bannerSurface = bannerSurface ?? throw new ArgumentNullException(nameof(bannerSurface));
        _queue = _window.DispatcherQueue;
    }

    public async Task StartAsync()
    {
        if (_pipe != null || _stopped)
            return;

        try
        {
            var baseDir = AppContext.BaseDirectory;
            var hostExe = Path.Combine(baseDir, "MgAdsHost", "Becetti.Security.MgAdsHost.exe");
            var configPath = Path.Combine(baseDir, "MgAds", "mgads.json");

            if (!File.Exists(hostExe))
            {
                LogLine("host executable not found; ads disabled (" + hostExe + ")");
                return;
            }
            if (!File.Exists(configPath))
            {
                LogLine("mgads.json not found; ads disabled (" + configPath + ")");
                return;
            }

            using (var doc = JsonDocument.Parse(await File.ReadAllTextAsync(configPath).ConfigureAwait(false)))
            {
                if (doc.RootElement.TryGetProperty("bannerUnitId", out var b))
                    _bannerUnitId = b.GetString();
                if (doc.RootElement.TryGetProperty("fullScreenUnitId", out var f))
                    _fullScreenUnitId = f.GetString();
            }

            _hwnd = WindowNative.GetWindowHandle(_window);
            var pipeName = "BecettiMgAds_" + Guid.NewGuid().ToString("N");

            _pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            _reader = new StreamReader(_pipe, new UTF8Encoding(false));
            _writer = new StreamWriter(_pipe, new UTF8Encoding(false)) { AutoFlush = true };

            _ = Task.Run(ReadLoopAsync);

            var psi = new ProcessStartInfo
            {
                FileName = hostExe,
                Arguments = $"--owner {_hwnd.ToInt64()} --pipe {pipeName} --config \"{configPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(hostExe)!
            };

            // WebView2 refuses to create its default user-data folder next to
            // an EXE inside C:\Program Files\WindowsApps (read-only). Point it
            // at a per-user writable location before the host starts.
            psi.Environment["WEBVIEW2_USER_DATA_FOLDER"] = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "BecettiSecurity", "WebView2");

            _process = Process.Start(psi);
            if (_process == null)
            {
                LogLine("Process.Start returned null; ads disabled");
                return;
            }

            _process.EnableRaisingEvents = true;
            _process.Exited += (_, _) =>
            {
                _ready = false;
                LogLine("host process exited (code " + SafeExitCode() + ")");
            };

            try
            {
                await _pipe.WaitForConnectionAsync().WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogLine("pipe connection failed: " + ex.Message);
                return;
            }

            LogLine("host connected; waiting for SDK READY");
            _queue.TryEnqueue(UpdateBannerLayout);
            Send("SHOWBANNER");
        }
        catch (Exception ex)
        {
            LogLine("startup failed: " + ex.Message);
            Stop();
        }
    }

    /// <summary>
    /// Requests the 1920x1080 full-screen unit. If the SDK is not ready yet
    /// the request is queued and sent as soon as READY arrives.
    /// </summary>
    public void QueueSplash()
    {
        if (_stopped)
            return;

        _splashPending = true;
        if (_ready)
            Send("SHOWSPLASH");
    }

    /// <summary>
    /// Computes the on-screen rectangle of AdBannerSurface in physical pixels
    /// and tells the host where to put its owned banner window. Must be
    /// called on the UI thread after the element is loaded.
    /// </summary>
    public void UpdateBannerLayout()
    {
        if (_stopped || !_ready || _hwnd == IntPtr.Zero)
            return;

        try
        {
            var xamlRoot = _bannerSurface.XamlRoot;
            if (xamlRoot == null)
                return;

            var scale = xamlRoot.RasterizationScale;
            if (_bannerSurface.ActualWidth < 10 || _bannerSurface.ActualHeight < 10)
                return;

            var point = _bannerSurface.TransformToVisual(null).TransformPoint(new Point(0, 0));

            if (!MgAdsNative.GetClientRect(_hwnd, out var client))
                return;

            var origin = new MgAdsNative.POINT { X = 0, Y = 0 };
            MgAdsNative.ClientToScreen(_hwnd, ref origin);

            var x = origin.X + (int)Math.Round(point.X * scale);
            var y = origin.Y + (int)Math.Round(point.Y * scale);
            var w = Math.Max(1, (int)Math.Round(_bannerSurface.ActualWidth * scale));
            var h = Math.Max(1, (int)Math.Round(_bannerSurface.ActualHeight * scale));

            Send($"LAYOUT {x} {y} {w} {h}");
        }
        catch (Exception ex)
        {
            LogLine("layout update failed: " + ex.Message);
        }
    }

    public void HideBanner()
    {
        if (!_stopped)
            Send("HIDEBANNER");
    }

    public void ShowBanner()
    {
        if (_stopped)
            return;
        Send("SHOWBANNER");
        _queue.TryEnqueue(UpdateBannerLayout);
    }

    public void Stop()
    {
        if (_stopped)
            return;

        _stopped = true;
        _ready = false;
        try { Send("SHUTDOWN"); } catch { }

        try
        {
            if (_process != null && !_process.HasExited)
            {
                if (!_process.WaitForExit(2500))
                    _process.Kill(entireProcessTree: true);
            }
        }
        catch { }

        try { _reader?.Dispose(); } catch { }
        try { _writer?.Dispose(); } catch { }
        try { _pipe?.Dispose(); } catch { }
        try { _process?.Dispose(); } catch { }
        _process = null;
        _pipe = null;
        _reader = null;
        _writer = null;
    }

    private async Task ReadLoopAsync()
    {
        var reader = _reader;
        if (reader == null)
            return;

        try
        {
            while (!_stopped)
            {
                var line = await reader.ReadLineAsync().ConfigureAwait(false);
                if (line == null)
                    break;

                line = line.Trim();
                if (line.Length == 0)
                    continue;

                _queue.TryEnqueue(() => HandleEvent(line));
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex)
        {
            LogLine("pipe read failed: " + ex.Message);
        }
    }

    private void HandleEvent(string line)
    {
        var parts = line.Split(' ');
        if (parts.Length == 0)
            return;

        switch (parts[0].ToUpperInvariant())
        {
            case "READY":
                _ready = true;
                LogLine("SDK READY");
                Send("SHOWBANNER");
                _queue.TryEnqueue(UpdateBannerLayout);
                if (_splashPending)
                    Send("SHOWSPLASH");
                break;

            case "ADCLOSE":
                if (parts.Length >= 2 &&
                    string.Equals(parts[1], _fullScreenUnitId, StringComparison.OrdinalIgnoreCase))
                {
                    _splashPending = false;
                    LogLine("full-screen ad closed" + (parts.Length >= 3 ? " status=" + parts[2] : ""));
                }
                break;

            case "ADCLICK":
                if (parts.Length >= 2)
                    LogLine("ad click unit=" + parts[1]);
                break;

            case "SPLASHCLOSED":
                _splashPending = false;
                LogLine("full-screen overlay closed");
                break;

            case "ERROR":
                LogLine("host error: " + (parts.Length > 1 ? string.Join(' ', parts, 1, parts.Length - 1) : "unknown"));
                break;
        }
    }

    private void Send(string line)
    {
        var writer = _writer;
        if (writer == null || _stopped)
            return;

        try
        {
            lock (_writeLock)
            {
                writer.WriteLine(line);
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex)
        {
            LogLine("send failed: " + ex.Message);
        }
    }

    private int SafeExitCode()
    {
        try { return _process?.HasExited == true ? _process.ExitCode : -1; }
        catch { return -1; }
    }

    private void LogLine(string message)
    {
        Debug.WriteLine("[MG Ads] " + message);
        Log?.Invoke(message);
    }
}

internal static class MgAdsNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);
}
