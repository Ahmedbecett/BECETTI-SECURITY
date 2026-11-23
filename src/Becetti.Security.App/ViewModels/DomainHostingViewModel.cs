using System.Collections.ObjectModel;
using System.Windows.Input;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Global Domain, Hosting, DNS &amp; IP Security Intelligence Hub ViewModel:
/// Full DNS Records + 4-Resolver Global Propagation + DNSSEC + Official IANA RDAP/WHOIS +
/// Real SSL/TLS &amp; HTTP Security Headers Audit + Email SPF/DMARC/DKIM/BIMI/MTA-STS +
/// Hosting IP/ASN/PTR/5-DNSBL/11-Port Probe + crt.sh Subdomain Discovery.
/// </summary>
public sealed class DomainHostingViewModel : ViewModelBase
{
    private readonly IDomainHostingIntelService _intel;
    private readonly ISettingsService _settings;
    private readonly IAiTriageNavigator _aiTriage;

    private string _queryInput = string.Empty;
    private bool _probeHostingPorts = true;
    private string _overallGrade = "—";
    private string _overallSummary = "Enter any domain (e.g. github.com), website URL, or IP address (e.g. 1.1.1.1) and click 'Run Complete Audit'.";
    private string _rdapSummary = "—";
    private string _rdapDetails = string.Empty;
    private string _sslSummary = "—";
    private string _sslCertDetails = string.Empty;
    private string _emailSummary = "—";
    private string _emailSpfDmarcDetails = string.Empty;
    private string _ipSummary = "—";
    private string _ipDetails = string.Empty;
    private string _subdomainsSummary = "—";
    private CompleteDomainHostingReport? _lastReport;

    public DomainHostingViewModel(
        IDomainHostingIntelService intel,
        ISettingsService settings,
        IAiTriageNavigator aiTriage)
    {
        _intel = intel;
        _settings = settings;
        _aiTriage = aiTriage;

        RunAuditCommand = new RelayCommand(RunAuditAsync);
        ExportHtmlCommand = new RelayCommand(ExportHtmlAsync);
        ExportJsonCommand = new RelayCommand(ExportJsonAsync);
        AskAiCommand = new RelayCommand(() => { AskAi(); return Task.CompletedTask; });
    }

    public ObservableCollection<DnsRecordItem> DnsRecords { get; } = new();
    public ObservableCollection<DnsPropagationCheck> PropagationChecks { get; } = new();
    public ObservableCollection<SecurityHeaderCheck> SecurityHeaders { get; } = new();
    public ObservableCollection<string> EmailRecommendations { get; } = new();
    public ObservableCollection<DnsblCheckResult> DnsblResults { get; } = new();
    public ObservableCollection<HostingPortProbeResult> PortProbes { get; } = new();
    public ObservableCollection<DiscoveredSubdomainItem> Subdomains { get; } = new();

    public ICommand RunAuditCommand { get; }
    public ICommand ExportHtmlCommand { get; }
    public ICommand ExportJsonCommand { get; }
    public ICommand AskAiCommand { get; }

    public string QueryInput { get => _queryInput; set => SetProperty(ref _queryInput, value); }
    public bool ProbeHostingPorts { get => _probeHostingPorts; set => SetProperty(ref _probeHostingPorts, value); }
    public string OverallGrade { get => _overallGrade; set => SetProperty(ref _overallGrade, value); }
    public string OverallSummary { get => _overallSummary; set => SetProperty(ref _overallSummary, value); }
    public string RdapSummary { get => _rdapSummary; set => SetProperty(ref _rdapSummary, value); }
    public string RdapDetails { get => _rdapDetails; set => SetProperty(ref _rdapDetails, value); }
    public string SslSummary { get => _sslSummary; set => SetProperty(ref _sslSummary, value); }
    public string SslCertDetails { get => _sslCertDetails; set => SetProperty(ref _sslCertDetails, value); }
    public string EmailSummary { get => _emailSummary; set => SetProperty(ref _emailSummary, value); }
    public string EmailSpfDmarcDetails { get => _emailSpfDmarcDetails; set => SetProperty(ref _emailSpfDmarcDetails, value); }
    public string IpSummary { get => _ipSummary; set => SetProperty(ref _ipSummary, value); }
    public string IpDetails { get => _ipDetails; set => SetProperty(ref _ipDetails, value); }
    public string SubdomainsSummary { get => _subdomainsSummary; set => SetProperty(ref _subdomainsSummary, value); }

    public async Task RunAuditAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            StatusMessage = $"Running live DNS, RDAP/WHOIS, SSL/TLS, Headers, Email, DNSBL & CT audit for '{QueryInput}'…";
            var res = await _intel.RunCompleteAuditAsync(QueryInput, ProbeHostingPorts);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            var r = res.Value;
            _lastReport = r;

            OverallGrade = $"{r.OverallGrade} ({r.OverallScore}/100)";
            OverallSummary = r.Summary;

            // DNS & Propagation
            DnsRecords.Clear();
            foreach (var d in r.DnsRecords) DnsRecords.Add(d);
            PropagationChecks.Clear();
            foreach (var p in r.PropagationChecks) PropagationChecks.Add(p);

            // WHOIS / RDAP
            RdapSummary = r.Rdap.Summary;
            RdapDetails =
                $"Domain: {r.Rdap.DomainName}\n" +
                $"Registrar: {r.Rdap.Registrar}\n" +
                $"Created: {(r.Rdap.CreatedDate.HasValue ? r.Rdap.CreatedDate.Value.ToString("yyyy-MM-dd") : "Unknown")} | " +
                $"Updated: {(r.Rdap.UpdatedDate.HasValue ? r.Rdap.UpdatedDate.Value.ToString("yyyy-MM-dd") : "Unknown")} | " +
                $"Expires: {(r.Rdap.ExpirationDate.HasValue ? $"{r.Rdap.ExpirationDate.Value:yyyy-MM-dd} ({r.Rdap.DaysUntilExpiry} days left)" : "Unknown")}\n" +
                $"EPP Locks: {(r.Rdap.StatusFlags.Count > 0 ? string.Join(", ", r.Rdap.StatusFlags) : "None reported")}\n" +
                $"Name Servers: {(r.Rdap.NameServers.Count > 0 ? string.Join(", ", r.Rdap.NameServers) : "None reported")}";

            // SSL & Hosting Headers
            SslSummary = r.SslHosting.Summary;
            SslCertDetails =
                $"TLS Protocol: {r.SslHosting.TlsProtocol} | HTTP->HTTPS Redirect: {(r.SslHosting.HttpRedirectsToHttps ? "YES" : "NO")} | HTTP Status: {r.SslHosting.HttpStatusCode}\n" +
                $"Host / CDN: {r.SslHosting.DetectedCdnOrHost} | Server: {r.SslHosting.ServerBanner} | X-Powered-By: {r.SslHosting.PoweredByBanner}\n" +
                $"Cert Issuer: {r.SslHosting.CertIssuer}\n" +
                $"Valid Until: {(r.SslHosting.ValidTo.HasValue ? $"{r.SslHosting.ValidTo.Value:yyyy-MM-dd} ({r.SslHosting.DaysRemaining} days left)" : "N/A")} | Thumbprint: {r.SslHosting.Thumbprint}\n" +
                $"SANs ({r.SslHosting.SubjectAltNames.Count}): {string.Join(", ", r.SslHosting.SubjectAltNames.Take(10))}";

            SecurityHeaders.Clear();
            foreach (var h in r.SslHosting.HeaderChecks) SecurityHeaders.Add(h);

            // Email Security
            EmailSummary = r.EmailSecurity.Summary;
            EmailSpfDmarcDetails =
                $"Mail Provider: {r.EmailSecurity.MailProviderGuess}\n" +
                $"MX Records: {(r.EmailSecurity.MxRecords.Count > 0 ? string.Join(" | ", r.EmailSecurity.MxRecords) : "None")}\n" +
                $"SPF: {r.EmailSecurity.SpfRecord} -> {r.EmailSecurity.SpfPolicyAssessment}\n" +
                $"DMARC: {r.EmailSecurity.DmarcRecord} -> {r.EmailSecurity.DmarcPolicyAssessment}\n" +
                $"DKIM Selectors Found: {(r.EmailSecurity.FoundDkimSelectors.Count > 0 ? string.Join(", ", r.EmailSecurity.FoundDkimSelectors) : "None matched standard selectors")} | " +
                $"MTA-STS: {(r.EmailSecurity.HasMtaSts ? "YES" : "NO")} | BIMI: {(r.EmailSecurity.HasBimi ? "YES" : "NO")}";

            EmailRecommendations.Clear();
            foreach (var rec in r.EmailSecurity.Recommendations) EmailRecommendations.Add(rec);

            // IP, Hosting, DNSBL & Ports
            IpSummary = r.IpHosting.Summary;
            IpDetails =
                $"IP: {r.IpHosting.IpAddress} | PTR: {r.IpHosting.ReversePtr}\n" +
                $"Hosting Org: {r.IpHosting.Organization} | ISP: {r.IpHosting.Isp} | ASN: {r.IpHosting.Asn}\n" +
                $"Location: {r.IpHosting.City}, {r.IpHosting.Country}\n" +
                $"Threat Feeds: {r.IpHosting.AbuseThreatFeedMatch}";

            DnsblResults.Clear();
            foreach (var d in r.IpHosting.DnsblResults) DnsblResults.Add(d);
            PortProbes.Clear();
            foreach (var p in r.IpHosting.PortProbes) PortProbes.Add(p);

            // Subdomains
            Subdomains.Clear();
            foreach (var s in r.Subdomains) Subdomains.Add(s);
            SubdomainsSummary = $"Certificate Transparency (crt.sh) discovered {r.Subdomains.Count} unique subdomain(s) for {r.NormalizedTarget}.";

            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task ExportHtmlAsync()
    {
        if (_lastReport is null) { ErrorMessage = "Run a Domain/Hosting/IP audit first."; return; }
        var safeName = _lastReport.NormalizedTarget.Replace(':', '_');
        var path = Path.Combine(_settings.DataDirectory, "reports", $"domain-audit-{safeName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.html");
        var res = await _intel.ExportHtmlReportAsync(_lastReport, path);
        if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
    }

    public async Task ExportJsonAsync()
    {
        if (_lastReport is null) { ErrorMessage = "Run a Domain/Hosting/IP audit first."; return; }
        var safeName = _lastReport.NormalizedTarget.Replace(':', '_');
        var path = Path.Combine(_settings.DataDirectory, "reports", $"domain-audit-{safeName}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        var res = await _intel.ExportJsonReportAsync(_lastReport, path);
        if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
    }

    private void AskAi()
    {
        if (_lastReport is null) return;
        _aiTriage.SendToBecettiAi(
            $"Review this real Domain, Hosting, DNS & IP Security Audit from BECETTI SECURITY:\n" +
            $"Target: {_lastReport.NormalizedTarget} | Overall Grade: {_lastReport.OverallGrade} ({_lastReport.OverallScore}/100)\n" +
            $"RDAP: {_lastReport.Rdap.Summary}\n" +
            $"SSL & Hosting: {_lastReport.SslHosting.Summary}\n" +
            $"Email Security: {_lastReport.EmailSecurity.Summary}\n" +
            $"IP / DNSBL / Ports: {_lastReport.IpHosting.Summary}\n" +
            $"Give concrete step-by-step recommendations to harden this domain, DNS, email, and hosting server.");
    }
}
