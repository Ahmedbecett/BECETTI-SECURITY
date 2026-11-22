using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Knowledge Base page: locally-authored security articles with simple search.</summary>
public sealed class KnowledgeBaseViewModel : ViewModelBase
{
    private readonly IKnowledgeBaseService _knowledgeBase;
    private string _searchText = string.Empty;

    public KnowledgeBaseViewModel(IKnowledgeBaseService knowledgeBase)
    {
        _knowledgeBase = knowledgeBase;
        SearchCommand = new RelayCommand(SearchAsync);
        Load();
    }

    public ObservableCollection<KnowledgeBaseArticle> Articles { get; } = new();

    public RelayCommand SearchCommand { get; }

    public string SearchText { get => _searchText; set => SetProperty(ref _searchText, value); }

    public void Load()
    {
        Articles.Clear();
        foreach (var article in _knowledgeBase.GetArticles())
            Articles.Add(article);

        StatusMessage = $"{Articles.Count} article(s).";
    }

    private Task SearchAsync()
    {
        Articles.Clear();
        foreach (var article in _knowledgeBase.Search(SearchText))
            Articles.Add(article);

        StatusMessage = $"{Articles.Count} article(s) match \"{SearchText}\".";
        return Task.CompletedTask;
    }
}
