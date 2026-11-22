using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class KnowledgeBaseServiceTests
{
    [Fact]
    public void GetArticles_ReturnsAtLeastOneArticlePerCoreTopic()
    {
        var service = new KnowledgeBaseService();

        var articles = service.GetArticles();

        Assert.NotEmpty(articles);
        Assert.All(articles, a =>
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Title));
            Assert.False(string.IsNullOrWhiteSpace(a.Body));
        });
    }

    [Fact]
    public void Search_MatchesByTitleCaseInsensitive()
    {
        var service = new KnowledgeBaseService();

        var results = service.Search("bitlocker");

        Assert.NotEmpty(results);
        Assert.Contains(results, a => a.Title.Contains("BitLocker", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Search_EmptyQuery_ReturnsAllArticles()
    {
        var service = new KnowledgeBaseService();

        var results = service.Search(string.Empty);

        Assert.Equal(service.GetArticles().Count, results.Count);
    }

    [Fact]
    public void Search_NoMatch_ReturnsEmptyRatherThanAllArticles()
    {
        var service = new KnowledgeBaseService();

        var results = service.Search("xyznonexistentquery123");

        Assert.Empty(results);
    }
}
