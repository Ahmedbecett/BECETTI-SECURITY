using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Knowledge Base: locally-authored security education articles bundled
/// with the app (no network call, no AI generation at read time) explaining
/// the real features BECETTI SECURITY itself exposes and general safe-use
/// practices.
/// </summary>
public interface IKnowledgeBaseService
{
    IReadOnlyList<KnowledgeBaseArticle> GetArticles();

    IReadOnlyList<KnowledgeBaseArticle> Search(string query);
}
