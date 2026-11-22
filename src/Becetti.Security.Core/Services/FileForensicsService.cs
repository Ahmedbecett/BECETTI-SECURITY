using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real local static PE analyzer, Shannon entropy calculator, and Windows Authenticode
/// digital signature verifier (WinVerifyTrust P/Invoke + X509Certificate2). Zero simulation.
/// </summary>
public sealed class FileForensicsService : IFileForensicsService
{
    private const long MaxReadBytes = 50 * 1024 * 1024; // 50 MB cap for in-memory static analysis

    private static readonly string[] WatchedApis =
    {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "QueueUserAPC",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "OpenProcess",
        "MiniDumpWriteDump",
        "CryptEncrypt",
        "BCryptEncrypt",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "URLDownloadToFile",
        "WinExec",
        "ShellExecute",
        "RegSetValueEx",
        "CreateService"
    };

    private static readonly string[] KnownPackerSectionNames =
    {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".vmp0", ".vmp1", ".themida", ".enigma", ".packed", ".mpress"
    };

    public async Task<OperationResult<FileForensicsReport>> AnalyzeFileAsync(string filePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return OperationResult<FileForensicsReport>.Fail("Selected file does not exist.", "FILE_NOT_FOUND");

        try
        {
            var fullPath = Path.GetFullPath(filePath);
            var info = new FileInfo(fullPath);
            if (info.Length > MaxReadBytes)
                return OperationResult<FileForensicsReport>.Fail($"File exceeds static analysis size limit ({MaxReadBytes / (1024 * 1024)} MB).", "FILE_TOO_LARGE");

            var bytes = await File.ReadAllBytesAsync(fullPath, ct).ConfigureAwait(false);
            var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var wholeEntropy = ComputeShannonEntropy(bytes);

            var sections = new List<PeSectionInfo>();
            var packerIndicators = new List<string>();
            var suspiciousApis = new List<string>();
            bool isPe = false;
            bool isDll = false;
            string arch = "Not a PE binary";
            DateTimeOffset? compileTime = null;

            if (TryParsePe(bytes, out arch, out compileTime, out isDll, sections, packerIndicators))
            {
                isPe = true;
                var asciiText = Encoding.ASCII.GetString(bytes);
                foreach (var api in WatchedApis)
                {
                    if (asciiText.Contains(api, StringComparison.Ordinal))
                        suspiciousApis.Add(api);
                }
            }

            var signature = VerifyAuthenticode(fullPath);

            // Compute transparent, rule-based risk assessment from real signals
            var reasons = new List<string>();
            int riskScore = 0;

            if (isPe && !signature.IsSigned)
            {
                riskScore += 15;
                reasons.Add("Executable is not digitally signed (unsigned PE binary).");
            }
            else if (signature.IsSigned && !signature.IsTrusted)
            {
                riskScore += 35;
                reasons.Add($"Authenticode signature failed trust validation ({signature.Status}).");
            }
            else if (signature.IsTrusted)
            {
                reasons.Add($"Valid trusted Authenticode signature: {signature.Subject}");
            }

            if (wholeEntropy >= 7.2)
            {
                riskScore += 25;
                reasons.Add($"High overall Shannon entropy ({wholeEntropy:F2}/8.00) — file is likely packed, compressed, or encrypted.");
            }

            foreach (var sec in sections)
            {
                if (sec.IsRwxAnomaly)
                {
                    riskScore += 25;
                    reasons.Add($"Section '{sec.Name}' is both Writable and Executable (RWX) — common in packers and self-modifying code.");
                }
                if (sec.IsHighEntropy)
                {
                    riskScore += 15;
                    reasons.Add($"Section '{sec.Name}' has high entropy ({sec.Entropy:F2}) — possible packed payload.");
                }
            }

            if (packerIndicators.Count > 0)
            {
                riskScore += 20;
                reasons.Add($"Packer/protector section names detected: {string.Join(", ", packerIndicators)}.");
            }

            if (suspiciousApis.Count >= 3)
            {
                riskScore += 25;
                reasons.Add($"References {suspiciousApis.Count} sensitive Windows APIs: {string.Join(", ", suspiciousApis.Take(6))}.");
            }
            else if (suspiciousApis.Count > 0)
            {
                riskScore += 10;
                reasons.Add($"References sensitive Windows API(s): {string.Join(", ", suspiciousApis)}.");
            }

            var riskLevel = riskScore >= 60 ? "High"
                : riskScore >= 30 ? "Medium"
                : "Low";

            if (reasons.Count == 0)
                reasons.Add("No static PE anomalies or high-entropy packing indicators detected.");

            var report = new FileForensicsReport
            {
                FilePath = fullPath,
                FileName = Path.GetFileName(fullPath),
                FileSizeBytes = bytes.LongLength,
                Sha256 = sha256,
                FileEntropy = Math.Round(wholeEntropy, 3),
                IsPeBinary = isPe,
                PeArchitecture = arch,
                PeCompileTimestampUtc = compileTime,
                IsDll = isDll,
                Sections = sections,
                SuspiciousApis = suspiciousApis,
                PackerIndicators = packerIndicators,
                Signature = signature,
                RiskAssessment = riskLevel,
                RiskReasons = reasons
            };

            return OperationResult<FileForensicsReport>.Ok(report, $"Static forensic analysis completed ({riskLevel} risk).");
        }
        catch (Exception ex)
        {
            return OperationResult<FileForensicsReport>.Fail($"Static file analysis failed: {ex.Message}", "FORENSICS_ERROR");
        }
    }

    internal static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return 0.0;

        Span<int> counts = stackalloc int[256];
        for (int i = 0; i < data.Length; i++)
            counts[data[i]]++;

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0)
                continue;
            double p = counts[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool TryParsePe(
        byte[] bytes,
        out string arch,
        out DateTimeOffset? compileTime,
        out bool isDll,
        List<PeSectionInfo> sections,
        List<string> packerIndicators)
    {
        arch = "Not a PE binary";
        compileTime = null;
        isDll = false;

        if (bytes.Length < 0x40 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
            return false;

        int peOffset = BitConverter.ToInt32(bytes, 0x3C);
        if (peOffset < 0 || peOffset + 24 > bytes.Length)
            return false;

        if (bytes[peOffset] != (byte)'P' || bytes[peOffset + 1] != (byte)'E' ||
            bytes[peOffset + 2] != 0 || bytes[peOffset + 3] != 0)
            return false;

        ushort machine = BitConverter.ToUInt16(bytes, peOffset + 4);
        ushort numberOfSections = BitConverter.ToUInt16(bytes, peOffset + 6);
        uint timestamp = BitConverter.ToUInt32(bytes, peOffset + 8);
        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(bytes, peOffset + 20);
        ushort characteristics = BitConverter.ToUInt16(bytes, peOffset + 22);

        arch = machine switch
        {
            0x8664 => "PE32+ (x64)",
            0x014C => "PE32 (x86)",
            0xAA64 => "PE32+ (ARM64)",
            _ => $"PE (Machine 0x{machine:X4})"
        };

        isDll = (characteristics & 0x2000) != 0;
        if (timestamp > 0)
            compileTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);

        int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
        int maxSections = Math.Min((int)numberOfSections, 64);

        for (int i = 0; i < maxSections; i++)
        {
            int off = sectionTableOffset + i * 40;
            if (off + 40 > bytes.Length)
                break;

            var nameRaw = Encoding.ASCII.GetString(bytes, off, 8).TrimEnd('\0', ' ');
            uint virtualSize = BitConverter.ToUInt32(bytes, off + 8);
            uint rawSize = BitConverter.ToUInt32(bytes, off + 16);
            uint rawPtr = BitConverter.ToUInt32(bytes, off + 20);
            uint secChars = BitConverter.ToUInt32(bytes, off + 36);

            double secEntropy = 0.0;
            if (rawSize > 0 && rawPtr < bytes.Length)
            {
                int safeLen = (int)Math.Min(rawSize, (uint)(bytes.Length - rawPtr));
                secEntropy = Math.Round(ComputeShannonEntropy(bytes.AsSpan((int)rawPtr, safeLen)), 3);
            }

            bool isExec = (secChars & 0x20000000) != 0;
            bool isWrite = (secChars & 0x80000000) != 0;

            sections.Add(new PeSectionInfo
            {
                Name = string.IsNullOrEmpty(nameRaw) ? $"sec_{i}" : nameRaw,
                VirtualSize = virtualSize,
                RawSize = rawSize,
                Entropy = secEntropy,
                IsExecutable = isExec,
                IsWritable = isWrite
            });

            foreach (var known in KnownPackerSectionNames)
            {
                if (nameRaw.Equals(known, StringComparison.OrdinalIgnoreCase) && !packerIndicators.Contains(nameRaw))
                    packerIndicators.Add(nameRaw);
            }
        }

        return true;
    }

    private static AuthenticodeInfo VerifyAuthenticode(string filePath)
    {
        if (!OperatingSystem.IsWindows())
            return new AuthenticodeInfo { IsSigned = false, IsTrusted = false, Status = "Windows Authenticode verification requires Windows." };

        string subject = string.Empty;
        string issuer = string.Empty;
        string thumbprint = string.Empty;
        DateTimeOffset? notAfter = null;
        bool hasEmbeddedCert = false;

        try
        {
#pragma warning disable SYSLIB0057
            using var baseCert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            using var cert2 = new X509Certificate2(baseCert);
            hasEmbeddedCert = true;
            subject = cert2.Subject;
            issuer = cert2.Issuer;
            thumbprint = cert2.Thumbprint;
            notAfter = new DateTimeOffset(cert2.NotAfter.ToUniversalTime());
        }
        catch
        {
            hasEmbeddedCert = false;
        }

        uint statusCode = VerifyEmbeddedSignatureWinTrust(filePath);
        if (statusCode == 0)
        {
            return new AuthenticodeInfo
            {
                IsSigned = true,
                IsTrusted = true,
                Status = "Valid (Trusted)",
                Subject = subject,
                Issuer = issuer,
                Thumbprint = thumbprint,
                NotAfter = notAfter
            };
        }

        // TRUST_E_NOSIGNATURE = 0x800B0100
        if (statusCode == 0x800B0100 && !hasEmbeddedCert)
        {
            return new AuthenticodeInfo
            {
                IsSigned = false,
                IsTrusted = false,
                Status = "Not Signed"
            };
        }

        var statusLabel = statusCode switch
        {
            0x800B0100 => "No Signature (Catalog-signed or unsigned)",
            0x800B010A => "Untrusted Root Certificate",
            0x80096010 => "Signature Tampered / Hash Mismatch",
            0x800B0101 => "Certificate Expired",
            0x800B010C => "Certificate Revoked",
            _ => $"Invalid / Untrusted (0x{statusCode:X8})"
        };

        return new AuthenticodeInfo
        {
            IsSigned = hasEmbeddedCert,
            IsTrusted = false,
            Status = statusLabel,
            Subject = subject,
            Issuer = issuer,
            Thumbprint = thumbprint,
            NotAfter = notAfter
        };
    }

    private static uint VerifyEmbeddedSignatureWinTrust(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(filePath),
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr fileInfoPtr = IntPtr.Zero;
        try
        {
            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE (fast offline check)
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = fileInfoPtr,
                dwStateAction = 1, // WTD_STATEACTION_VERIFY
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = 0x00000010, // WTD_REVOCATION_CHECK_NONE
                dwUIContext = 0
            };

            Guid actionGuid = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            uint result = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref data);

            // Clean up WinTrust state handle
            data.dwStateAction = 2; // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref data);
            return result;
        }
        finally
        {
            if (fileInfo.pcwszFilePath != IntPtr.Zero)
                Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
            if (fileInfoPtr != IntPtr.Zero)
                Marshal.FreeCoTaskMem(fileInfoPtr);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, [In] ref Guid pgActionID, [In, Out] ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }
}
