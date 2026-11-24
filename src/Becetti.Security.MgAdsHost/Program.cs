using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace Becetti.Security.MgAdsHost
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            // --probe: load the config and the real MG Ads assembly on the
            // .NET Framework runtime, then exit. Used by CI to prove the SDK
            // payload is present and loadable without showing a window.
            if (HasArg(args, "--probe"))
            {
                try
                {
                    var configPath = GetArg(args, "--config");
                    var probeConfig = MgAdsConfig.Load(configPath);

                    var sdkPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MiracleGamesAd.dll");
                    var assembly = Assembly.LoadFrom(sdkPath);
                    var advertManager = assembly.GetType("MiracleGamesAd.AdvertManager", throwOnError: true);
                    var applicationManager = assembly.GetType("MiracleGamesAd.ApplicationManager", throwOnError: true);

                    Console.WriteLine("PROBE OK sdk=" + assembly.GetName().Version +
                                      " advertManager=" + (advertManager != null) +
                                      " applicationManager=" + (applicationManager != null) +
                                      " appId=" + probeConfig.AppId);
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("PROBE FAIL " + ex);
                    return 1;
                }
            }

            string owner = null;
            string pipe = null;
            string config = null;
            try
            {
                owner = GetArg(args, "--owner");
                pipe = GetArg(args, "--pipe");
                config = GetArg(args, "--config");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ARG FAIL " + ex.Message);
                return 2;
            }

            try
            {
                NativeMethods.MakeDpiAware();
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += (_, e) => HostLog.Error("UI thread exception: " + e.Exception);
                AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                    HostLog.Error("Unhandled exception: " + e.ExceptionObject);

                Application.Run(new AdHostContext(owner, pipe, config));
                return 0;
            }
            catch (Exception ex)
            {
                HostLog.Error("host failed: " + ex);
                Console.Error.WriteLine("HOST FAIL " + ex);
                return 1;
            }
        }

        private static bool HasArg(string[] args, string name)
        {
            for (var i = 0; i < args.Length; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private static string GetArg(string[] args, string name)
        {
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            }
            throw new ArgumentException("Missing required argument " + name);
        }
    }
}
