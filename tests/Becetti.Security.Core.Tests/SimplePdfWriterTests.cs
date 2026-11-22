using System.Text;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class SimplePdfWriterTests
{
    [Fact]
    public void Write_ProducesAStructurallyValidSinglePagePdf()
    {
        var bytes = SimplePdfWriter.Write("Test Report", new[] { "Line one", "Line two" });
        var text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        Assert.StartsWith("%PDF-1.4", text);
        Assert.Contains("%%EOF", text);
        Assert.Contains("/Type /Catalog", text);
        Assert.Contains("/Type /Pages", text);
        Assert.Contains("xref", text);
        Assert.Contains("trailer", text);
        Assert.Contains("Line one", text);
    }

    [Fact]
    public void Write_ManyLines_SpansMultiplePageObjects()
    {
        var manyLines = Enumerable.Range(1, 200).Select(i => $"Finding line {i}").ToList();

        var bytes = SimplePdfWriter.Write("Long Report", manyLines);
        var text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        // More than one /Type /Page object means pagination actually happened.
        var pageObjectCount = System.Text.RegularExpressions.Regex.Matches(text, @"/Type /Page[^s]").Count;
        Assert.True(pageObjectCount > 1, "Expected multiple pages for 200 lines of content.");
        Assert.Contains("Finding line 200", text);
    }

    [Fact]
    public void Write_ParenthesesAndBackslashesInText_AreEscapedSafely()
    {
        var bytes = SimplePdfWriter.Write("Title", new[] { "Path (C:\\Users\\test) has a backslash" });
        var text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        Assert.Contains("\\(C:\\\\Users\\\\test\\)", text);
    }
}
