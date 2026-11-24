using System;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using MiracleGamesAd;
using MiracleGamesAd.Models;
using Newtonsoft.Json.Linq;

namespace Becetti.Security.MgAdsHost
{
    /// <summary>
    /// Owns the MG Ads SDK lifecycle, the banner/splash windows and the
    /// command pipe. It runs on the WinForms UI thread (Application.Run with
    /// an ApplicationContext), which is what the MG Ads WinForms SDK needs.
    /// </summary>
    internal sealed class AdHostContext : ApplicationContext
    {
        private readonly IntPtr _owner;
        private readonly string _configPath;
        private readonly PipeClient _pipe;
        private readonly System.Windows.Forms.Timer _ownerTimer;

        private MgAdsConfig _config;
        private SynchronizationContext _ui;
        private BannerForm _banner;
        private SplashForm _splash;
        private Rectangle _bannerRect = Rectangle.Empty;
        private bool _bannerVisible = true;
        private bool _ownerMinimized;
        private bool _initialized;

        public AdHostContext(string ownerHwnd, string pipeName, string configPath)
        {
            if (string.IsNullOrWhiteSpace(ownerHwnd))
                throw new ArgumentException("owner hwnd is required", nameof(ownerHwnd));
            if (string.IsNullOrWhiteSpace(pipeName))
                throw new ArgumentException("pipe name is required", nameof(pipeName));

            _owner = new IntPtr(long.Parse(ownerHwnd));
            _configPath = configPath;

            HostLog.Info("host starting; owner=0x" + _owner.ToInt64().ToString("X") +
                         " pipe=" + pipeName);

            _pipe = new PipeClient(pipeName);
            _pipe.CommandReceived += OnPipeCommand;
            _pipe.Start();

            _ownerTimer = new System.Windows.Forms.Timer { Interval = 200 };
            _ownerTimer.Tick += OnOwnerTimerTick;
            _ownerTimer.Start();

            // Application.Run installs the SynchronizationContext when the
            // message loop starts. Starting initialization from a timer tick
            // guarantees every await continuation runs on the UI thread.
            var kick = new System.Windows.Forms.Timer { Interval = 150 };
            kick.Tick += async (_, _) =>
            {
                kick.Stop();
                kick.Dispose();
                await InitializeAsync().ConfigureAwait(true);
            };
            kick.Start();
        }

        private async Task InitializeAsync()
        {
            _ui = SynchronizationContext.Current ?? new SynchronizationContext();

            try
            {
                _config = MgAdsConfig.Load(_configPath);
                HostLog.Info("config loaded; banner=" + _config.BannerUnitId +
                             " fullScreen=" + _config.FullScreenUnitId);

                AdvertManager.AdCloseEvent += OnAdClose;
                AdvertManager.AdClickEvent += OnAdClick;

                // Mandatory MG Ads order: SetAppId -> OpenCmp -> Initialize.
                ApplicationManager.SetAppId(_config.AppId, _config.SecretKey);

                var cmp = await ApplicationManager.OpenCmp(new CmpParameters
                {
                    IgnoreExpiredCheck = false
                }).ConfigureAwait(true);
                HostLog.Info("OpenCmp returned " + (cmp != null ? cmp.ReturnValue.ToString() : "null"));

                var init = await ApplicationManager.Initialize().ConfigureAwait(true);
                if (init == null || !init.ReturnValue)
                {
                    var detail = init != null && init.Data != null ? init.Data.ToString() : "unknown";
                    HostLog.Error("MG Ads Initialize failed: " + detail);
                    _pipe.Send("ERROR Initialize failed: " + detail);
                    Application.Exit();
                    return;
                }

                HostLog.Info("MG Ads initialized successfully");
                _initialized = true;

                _banner = new BannerForm();
                _banner.Show();
                NativeMethods.SetOwner(_banner.Handle, _owner);
                ApplyBannerLayout();

                var bannerResult = await AdvertManager.ShowAd(
                    _banner, _config.BannerUnitId, AdType.Banner).ConfigureAwait(true);
                HostLog.Info("banner ShowAd returned " +
                             (bannerResult != null ? bannerResult.ReturnValue.ToString() : "null"));

                _pipe.Send("READY");
            }
            catch (Exception ex)
            {
                HostLog.Error("initialization exception: " + ex);
                _pipe.Send("ERROR " + Flatten(ex));
                Application.Exit();
            }
        }

        private void OnPipeCommand(string line)
        {
            // Pipe reads run on a thread-pool thread. Marshal every UI action.
            if (_ui == null)
                return;

            _ui.Post(_ => HandleCommand(line), null);
        }

        private void HandleCommand(string line)
        {
            var parts = line.Split(' ');
            if (parts.Length == 0)
                return;

            switch (parts[0].ToUpperInvariant())
            {
                case "LAYOUT":
                    if (parts.Length >= 5)
                    {
                        int x, y, w, h;
                        if (int.TryParse(parts[1], out x) && int.TryParse(parts[2], out y) &&
                            int.TryParse(parts[3], out w) && int.TryParse(parts[4], out h) &&
                            w > 0 && h > 0)
                        {
                            _bannerRect = new Rectangle(x, y, w, h);
                            ApplyBannerLayout();
                        }
                    }
                    break;

                case "SHOWBANNER":
                    _bannerVisible = true;
                    ApplyBannerLayout();
                    break;

                case "HIDEBANNER":
                    _bannerVisible = false;
                    if (_banner != null && _banner.IsHandleCreated)
                        _banner.Hide();
                    break;

                case "SHOWSPLASH":
                    _ = ShowSplashAsync();
                    break;

                case "SHUTDOWN":
                    HostLog.Info("SHUTDOWN received");
                    Application.Exit();
                    break;
            }
        }

        private async Task ShowSplashAsync()
        {
            if (!_initialized || _splash != null)
                return;

            try
            {
                _splash = new SplashForm();
                _splash.Show();
                NativeMethods.SetOwner(_splash.Handle, _owner);
                ApplySplashLayout();

                var result = await AdvertManager.ShowAd(
                    _splash, _config.FullScreenUnitId, AdType.FullScreen).ConfigureAwait(true);
                HostLog.Info("full-screen ShowAd returned " +
                             (result != null ? result.ReturnValue.ToString() : "null"));

                if (result == null || !result.ReturnValue)
                    CloseSplash();
            }
            catch (Exception ex)
            {
                HostLog.Error("full-screen ad exception: " + ex);
                _pipe.Send("ERROR " + Flatten(ex));
                CloseSplash();
            }
        }

        private void CloseSplash()
        {
            if (_splash == null)
                return;

            try
            {
                _splash.Close();
                _splash.Dispose();
            }
            catch { }
            _splash = null;
            _pipe.Send("SPLASHCLOSED");
        }

        private void OnAdClose(object sender, string json)
        {
            string unitId = null;
            string status = null;
            try
            {
                var obj = JObject.Parse(json ?? "{}");
                unitId = (string)obj["unitId"];
                status = obj["advertStatus"] != null ? obj["advertStatus"].ToString() : null;
            }
            catch { }

            HostLog.Info("AdCloseEvent unit=" + (unitId ?? "?") + " status=" + (status ?? "?") + " raw=" + json);
            _pipe.Send("ADCLOSE " + (unitId ?? string.Empty) + " " + (status ?? string.Empty));

            if (_config != null && _splash != null &&
                string.Equals(unitId, _config.FullScreenUnitId, StringComparison.OrdinalIgnoreCase))
            {
                if (_ui != null)
                    _ui.Post(_ => CloseSplash(), null);
            }
        }

        private void OnAdClick(object sender, string json)
        {
            string unitId = null;
            try
            {
                var obj = JObject.Parse(json ?? "{}");
                unitId = (string)obj["unitId"];
            }
            catch { }

            HostLog.Info("AdClickEvent unit=" + (unitId ?? "?") + " raw=" + json);
            _pipe.Send("ADCLICK " + (unitId ?? string.Empty));
        }

        private void OnOwnerTimerTick(object sender, EventArgs e)
        {
            if (_owner == IntPtr.Zero || !NativeMethods.IsWindow(_owner))
            {
                HostLog.Info("owner window gone; exiting");
                Application.Exit();
                return;
            }

            bool minimized;
            try { minimized = NativeMethods.IsIconic(_owner); }
            catch { minimized = false; }

            if (minimized == _ownerMinimized)
            {
                if (!minimized && _splash != null && _splash.IsHandleCreated)
                    ApplySplashLayout();
                return;
            }

            _ownerMinimized = minimized;
            HostLog.Info("owner minimized=" + minimized);

            if (minimized)
            {
                if (_banner != null && _banner.IsHandleCreated) _banner.Hide();
                if (_splash != null && _splash.IsHandleCreated) _splash.Hide();
            }
            else
            {
                if (_bannerVisible) ApplyBannerLayout();
                if (_splash != null && _splash.IsHandleCreated)
                {
                    _splash.Show();
                    ApplySplashLayout();
                }
            }
        }

        private void ApplyBannerLayout()
        {
            if (_banner == null || !_banner.IsHandleCreated)
                return;

            var rect = _bannerRect;
            if (rect.Width <= 0 || rect.Height <= 0)
            {
                // Fallback: centered 728x90 strip at the bottom of the owner
                // client area, above the footer. The app normally sends an
                // exact LAYOUT before the SDK finishes initializing.
                var client = NativeMethods.ClientRectOnScreen(_owner);
                if (client.Width > 0 && client.Height > 0)
                {
                    rect = new Rectangle(
                        client.Left + Math.Max(0, (client.Width - 728) / 2),
                        client.Bottom - 90,
                        Math.Min(728, client.Width),
                        90);
                }
            }

            _banner.Bounds = rect;

            if (_bannerVisible && !_ownerMinimized)
                _banner.Show();
            else
                _banner.Hide();
        }

        private void ApplySplashLayout()
        {
            if (_splash == null || !_splash.IsHandleCreated)
                return;

            var client = NativeMethods.ClientRectOnScreen(_owner);
            if (client.Width > 0 && client.Height > 0)
                _splash.Bounds = client;
        }

        private static string Flatten(Exception ex)
        {
            if (ex == null) return "unknown";
            var sb = new System.Text.StringBuilder();
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (sb.Length > 0) sb.Append(" <- ");
                sb.Append(e.GetType().Name).Append(": ").Append(e.Message);
            }
            return sb.ToString().Replace("\r", " ").Replace("\n", " ");
        }

        protected override void ExitThreadCore()
        {
            try { _ownerTimer.Stop(); _ownerTimer.Dispose(); } catch { }
            try
            {
                if (_splash != null) { _splash.Close(); _splash.Dispose(); _splash = null; }
                if (_banner != null) { _banner.Close(); _banner.Dispose(); _banner = null; }
            }
            catch { }
            try { _pipe.Dispose(); } catch { }
            HostLog.Info("host exiting");
            base.ExitThreadCore();
        }
    }
}
