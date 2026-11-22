using System.Text;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Writes a minimal, valid, text-only PDF (one Type1 Helvetica font, plain
/// left-aligned lines, automatic pagination) with no external dependency.
/// This keeps the Smart Security Reports PDF export self-contained and
/// avoids pulling in a third-party PDF package the CI build would need to
/// restore from an unreviewed source. Only Latin-1/WinAnsi-range characters
/// render correctly, so callers should keep report text in English.
/// </summary>
internal static class SimplePdfWriter
{
    private const double PageWidth = 612;  // US Letter, points
    private const double PageHeight = 792;
    private const double MarginLeft = 54;
    private const double MarginTop = 54;
    private const double MarginBottom = 54;
    private const double LineHeight = 14.5;
    private const int FontSize = 11;

    public static byte[] Write(string documentTitle, IReadOnlyList<string> lines)
    {
        var usableHeight = PageHeight - MarginTop - MarginBottom;
        var linesPerPage = Math.Max(1, (int)(usableHeight / LineHeight));

        var pages = new List<IReadOnlyList<string>>();
        for (var i = 0; i < lines.Count; i += linesPerPage)
            pages.Add(lines.Skip(i).Take(linesPerPage).ToList());
        if (pages.Count == 0)
            pages.Add(Array.Empty<string>());

        var objects = new List<string>();

        // 1: Catalog, 2: Pages, 3: Font. Pages start at object 4, then one content
        // stream object per page immediately follows all page objects.
        var pageCount = pages.Count;
        var firstPageObj = 4;
        var firstContentObj = firstPageObj + pageCount;

        var pageKids = string.Join(" ", Enumerable.Range(firstPageObj, pageCount).Select(n => $"{n} 0 R"));

        objects.Add("<< /Type /Catalog /Pages 2 0 R >>");
        objects.Add($"<< /Type /Pages /Kids [{pageKids}] /Count {pageCount} >>");
        objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

        for (var p = 0; p < pageCount; p++)
        {
            var contentObjNum = firstContentObj + p;
            objects.Add(
                $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PageWidth} {PageHeight}] " +
                $"/Resources << /Font << /F1 3 0 R >> >> /Contents {contentObjNum} 0 R >>");
        }

        for (var p = 0; p < pageCount; p++)
        {
            var content = BuildPageContent(pages[p], p == 0 ? documentTitle : null);
            var bytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(content);
            objects.Add($"<< /Length {bytes.Length} >>\nstream\n{content}\nendstream");
        }

        return AssemblePdf(objects);
    }

    private static string BuildPageContent(IReadOnlyList<string> lines, string? title)
    {
        var sb = new StringBuilder();
        sb.Append("BT\n");
        sb.Append($"/F1 {FontSize} Tf\n");
        sb.Append($"{LineHeight} TL\n");
        sb.Append($"{MarginLeft} {PageHeight - MarginTop} Td\n");

        var first = true;
        if (title is not null)
        {
            sb.Append($"/F1 16 Tf\n({Escape(title)}) Tj\n");
            sb.Append($"/F1 {FontSize} Tf\n");
            sb.Append("T*\nT*\n");
            first = false;
        }

        foreach (var line in lines)
        {
            if (!first)
                sb.Append("T*\n");
            sb.Append($"({Escape(line)}) Tj\n");
            first = false;
        }

        sb.Append("ET");
        return sb.ToString();
    }

    private static string Escape(string text)
    {
        // Keep only characters the WinAnsi/Helvetica base encoding can render; anything
        // outside Latin-1 becomes '?' rather than corrupting the PDF's byte stream.
        var safe = new StringBuilder(text.Length);
        foreach (var c in text)
            safe.Append(c <= 0xFF ? c : '?');

        return safe.ToString()
            .Replace("\\", "\\\\")
            .Replace("(", "\\(")
            .Replace(")", "\\)");
    }

    private static byte[] AssemblePdf(IReadOnlyList<string> objects)
    {
        using var stream = new MemoryStream();
        var offsets = new int[objects.Count + 1];

        void WriteAscii(string s)
        {
            var bytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(s);
            stream.Write(bytes, 0, bytes.Length);
        }

        WriteAscii("%PDF-1.4\n");

        for (var i = 0; i < objects.Count; i++)
        {
            offsets[i + 1] = (int)stream.Position;
            WriteAscii($"{i + 1} 0 obj\n{objects[i]}\nendobj\n");
        }

        var xrefStart = (int)stream.Position;
        WriteAscii($"xref\n0 {objects.Count + 1}\n");
        WriteAscii("0000000000 65535 f \n");
        for (var i = 1; i <= objects.Count; i++)
            WriteAscii($"{offsets[i]:D10} 00000 n \n");

        WriteAscii($"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R >>\nstartxref\n{xrefStart}\n%%EOF");

        return stream.ToArray();
    }
}
