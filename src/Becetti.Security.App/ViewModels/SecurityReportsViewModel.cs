using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Smart Security Reports page: builds a consolidated report from real,
/// already-verified checks and exposes plain-text/PDF rendering for export.
/// </summary>
public sealed class SecurityReportsViewModel : ViewModelBase
{
    private readonly ISecurityReportService _reports;

    private SecurityReportSummary _report = new();

    public SecurityReportsViewModel(ISecurityReportService reports)
    {
        _reports = reports;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

    public SecurityReportSummary Report { get => _report; set => SetProperty(ref _report, value); }

    public string ReportText => _reports.RenderText(Report);

    public bool HasReport { get; private set; }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _reports.BuildReportAsync();
            if (result.Success && result.Value is not null)
            {
                Report = result.Value;
                HasReport = true;
                StatusMessage = result.Message;
            }
            else
            {
                ErrorMessage = result.Message;
            }

            OnPropertyChanged(nameof(ReportText));
            OnPropertyChanged(nameof(HasReport));
        }
        finally
        {
            IsBusy = false;
        }
    }

    public byte[] RenderPdf() => _reports.RenderPdf(Report);

    public string RenderText() => _reports.RenderText(Report);
}
