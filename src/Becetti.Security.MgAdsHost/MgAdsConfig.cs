using System;
using System.IO;
using Newtonsoft.Json;

namespace Becetti.Security.MgAdsHost
{
    /// <summary>
    /// Mirrors the values written by the app in MgAds/mgads.json. The app
    /// owns the file; this host only reads it, so ad units can be changed
    /// without rebuilding the host.
    /// </summary>
    public sealed class MgAdsConfig
    {
        [JsonProperty("appId")]
        public string AppId { get; set; }

        [JsonProperty("secretKey")]
        public string SecretKey { get; set; }

        [JsonProperty("bannerUnitId")]
        public string BannerUnitId { get; set; }

        [JsonProperty("fullScreenUnitId")]
        public string FullScreenUnitId { get; set; }

        public static MgAdsConfig Load(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                throw new FileNotFoundException("MG Ads config was not found.", path);

            var json = File.ReadAllText(path);
            var cfg = JsonConvert.DeserializeObject<MgAdsConfig>(json);
            if (cfg == null)
                throw new InvalidDataException("MG Ads config is empty or invalid JSON.");

            if (string.IsNullOrWhiteSpace(cfg.AppId) || cfg.AppId.IndexOf("REPLACE", StringComparison.OrdinalIgnoreCase) >= 0)
                throw new InvalidDataException("MG Ads AppId is not configured (mgads.json).");
            if (string.IsNullOrWhiteSpace(cfg.SecretKey))
                throw new InvalidDataException("MG Ads SecretKey is not configured (mgads.json).");
            if (string.IsNullOrWhiteSpace(cfg.BannerUnitId))
                throw new InvalidDataException("MG Ads BannerUnitId is not configured (mgads.json).");
            if (string.IsNullOrWhiteSpace(cfg.FullScreenUnitId))
                throw new InvalidDataException("MG Ads FullScreenUnitId is not configured (mgads.json).");

            return cfg;
        }
    }
}
