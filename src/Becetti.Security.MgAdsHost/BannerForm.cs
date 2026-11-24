using System.Drawing;
using System.Windows.Forms;

namespace Becetti.Security.MgAdsHost
{
    /// <summary>
    /// Borderless 728x90 owned window that hosts the MG Ads banner control.
    /// It is a separate top-level HWND because the MG Ads SDK is a WinForms
    /// control tree; it is positioned exactly over the reserved banner
    /// surface in the WinUI 3 layout by the app's LAYOUT command.
    /// </summary>
    internal sealed class BannerForm : Form
    {
        public BannerForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Color.FromArgb(5, 7, 11);
            Text = "BECETTI SECURITY — MG Ads banner";
            ClientSize = new Size(728, 90);
            DoubleBuffered = true;
        }

        protected override bool ShowWithoutActivation
        {
            get { return true; }
        }

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= (int)(NativeMethods.WS_EX_TOOLWINDOW | NativeMethods.WS_EX_NOACTIVATE);
                return cp;
            }
        }
    }
}
