using System.Text;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Manages blocked domains via the real Windows hosts file. Each BECETTI
/// SECURITY entry is written as "0.0.0.0 &lt;domain&gt; # BECETTI-PARENTAL"
/// so it is unambiguous which lines belong to this feature.
/// </summary>
public sealed class ParentalControlService : IParentalControlService
{
    private const string Tag = "# BECETTI-PARENTAL";
    private readonly string _hostsPath;

    public ParentalControlService(string? hostsPathOverride = null)
    {
        _hostsPath = hostsPathOverride ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");
    }

    public bool CanManageBlocklist => ElevationHelper.IsElevated();

    public async Task<OperationResult<IReadOnlyList<BlockedDomainInfo>>> GetBlockedDomainsAsync(CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(_hostsPath))
                return OperationResult<IReadOnlyList<BlockedDomainInfo>>.Ok(Array.Empty<BlockedDomainInfo>(), "No hosts file found.");

            var lines = await File.ReadAllLinesAsync(_hostsPath, ct).ConfigureAwait(false);
            var domains = new List<BlockedDomainInfo>();

            foreach (var line in lines)
            {
                if (!line.Contains(Tag, StringComparison.Ordinal))
                    continue;

                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                    domains.Add(new BlockedDomainInfo { Domain = parts[1] });
            }

            return OperationResult<IReadOnlyList<BlockedDomainInfo>>.Ok(domains, $"{domains.Count} blocked domain(s).");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<BlockedDomainInfo>>.Fail($"Could not read the hosts file: {ex.Message}", "ERROR");
        }
    }

    public async Task<OperationResult> BlockDomainAsync(string domain, CancellationToken ct = default)
    {
        domain = NormalizeDomain(domain);
        if (string.IsNullOrWhiteSpace(domain))
            return OperationResult.Fail("Enter a domain, e.g. example.com.", "BAD_REQUEST");

        if (!CanManageBlocklist)
            return OperationResult.Fail("Blocking a website requires Administrator. Restart BECETTI SECURITY as administrator from Settings.", "ELEVATION_REQUIRED");

        try
        {
            var existing = await GetBlockedDomainsAsync(ct).ConfigureAwait(false);
            if (existing.Value?.Any(d => string.Equals(d.Domain, domain, StringComparison.OrdinalIgnoreCase)) == true)
                return OperationResult.Ok($"{domain} is already blocked.");

            var line = $"0.0.0.0 {domain} {Tag}";
            await using var writer = new StreamWriter(_hostsPath, append: true, Encoding.ASCII);
            await writer.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);

            return OperationResult.Ok($"{domain} is now blocked on this device.");
        }
        catch (UnauthorizedAccessException)
        {
            return OperationResult.Fail("Access denied writing the hosts file. Make sure BECETTI SECURITY is running as administrator.", "ACCESS_DENIED");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not block {domain}: {ex.Message}", "ERROR");
        }
    }

    public async Task<OperationResult> UnblockDomainAsync(string domain, CancellationToken ct = default)
    {
        domain = NormalizeDomain(domain);
        if (string.IsNullOrWhiteSpace(domain))
            return OperationResult.Fail("No domain given.", "BAD_REQUEST");

        if (!CanManageBlocklist)
            return OperationResult.Fail("Unblocking a website requires Administrator. Restart BECETTI SECURITY as administrator from Settings.", "ELEVATION_REQUIRED");

        try
        {
            if (!File.Exists(_hostsPath))
                return OperationResult.Ok($"{domain} was not blocked.");

            var lines = await File.ReadAllLinesAsync(_hostsPath, ct).ConfigureAwait(false);
            var kept = lines.Where(l => !(l.Contains(Tag, StringComparison.Ordinal) &&
                                           l.Contains(domain, StringComparison.OrdinalIgnoreCase))).ToArray();

            if (kept.Length == lines.Length)
                return OperationResult.Ok($"{domain} was not blocked.");

            await File.WriteAllLinesAsync(_hostsPath, kept, Encoding.ASCII, ct).ConfigureAwait(false);
            return OperationResult.Ok($"{domain} is no longer blocked.");
        }
        catch (UnauthorizedAccessException)
        {
            return OperationResult.Fail("Access denied writing the hosts file. Make sure BECETTI SECURITY is running as administrator.", "ACCESS_DENIED");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not unblock {domain}: {ex.Message}", "ERROR");
        }
    }

    private static string NormalizeDomain(string domain)
    {
        domain = domain.Trim().ToLowerInvariant();
        domain = domain.Replace("https://", string.Empty).Replace("http://", string.Empty);
        var slash = domain.IndexOf('/');
        if (slash >= 0)
            domain = domain[..slash];
        return domain;
    }
}
