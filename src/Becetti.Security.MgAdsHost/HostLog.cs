using System;
using System.IO;

namespace Becetti.Security.MgAdsHost
{
    /// <summary>
    /// Small append-only diagnostic log. The app never depends on it; it is
    /// there so a real-device test can prove what the SDK did (init result,
    /// ad request, callback) without attaching a debugger.
    /// </summary>
    internal static class HostLog
    {
        private static readonly object Gate = new object();
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity", "mgads-host.log");

        public static void Info(string message)
        {
            Write("INFO", message);
        }

        public static void Error(string message)
        {
            Write("ERROR", message);
        }

        private static void Write(string level, string message)
        {
            try
            {
                lock (Gate)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(LogPath));
                    File.AppendAllText(LogPath,
                        DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'") +
                        " [" + level + "] " + message + Environment.NewLine);
                }
            }
            catch
            {
                // Diagnostics must never take the ad host down.
            }
        }
    }
}
