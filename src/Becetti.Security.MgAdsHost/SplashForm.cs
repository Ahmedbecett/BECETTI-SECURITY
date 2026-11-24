using System.Drawing;
using System.Windows.Forms;

namespace Becetti.Security.MgAdsHost
{
    /// <summary>
    /// Borderless full-client-area owned window used for the MG Ads
    /// 1920x1080 full-screen unit. The SDK scales the creative into this
    /// container; on close (AdCloseEvent) the host closes the form.
    /// </summary>
    internal sealed class SplashForm : Form
    {
        public SplashForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Color.FromArgb(5, 7, 11);
            Text = "BECETTI SECURITY — MG Ads full-screen";
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
