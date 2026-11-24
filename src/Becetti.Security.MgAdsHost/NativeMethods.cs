using System;
using System.Drawing;
using System.Runtime.InteropServices;

namespace Becetti.Security.MgAdsHost
{
    internal static class NativeMethods
    {
        public const int GWL_HWNDPARENT = -8;
        public const uint WS_EX_TOOLWINDOW = 0x00000080;
        public const uint WS_EX_NOACTIVATE = 0x08000000;
        public const int SW_SHOWNOACTIVATE = 4;

        private static readonly IntPtr DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = new IntPtr(-4);

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int X;
            public int Y;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint flags);

        [DllImport("user32.dll")]
        private static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

        [DllImport("shcore.dll")]
        private static extern int SetProcessDpiAwareness(int awareness);

        public static void MakeDpiAware()
        {
            // Per-Monitor V2 (Windows 10 1703+). Fall back to the older
            // shcore API, then to system-aware. The app sends physical pixel
            // coordinates, so the host must not be DPI-virtualized.
            try
            {
                if (SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
                    return;
            }
            catch { }

            try { SetProcessDpiAwareness(2); }
            catch { }
        }

        public static void SetOwner(IntPtr hWnd, IntPtr ownerHwnd)
        {
            if (hWnd == IntPtr.Zero || ownerHwnd == IntPtr.Zero)
                return;

            // GWL_HWNDPARENT turns a top-level window into an owned window:
            // it stays above its owner, is hidden when the owner minimizes,
            // and never appears in the taskbar/Alt+Tab list of its own.
            SetWindowLongPtr(hWnd, GWL_HWNDPARENT, ownerHwnd);
        }

        public static Rectangle ClientRectOnScreen(IntPtr hWnd)
        {
            RECT rect;
            if (!GetClientRect(hWnd, out rect))
                return Rectangle.Empty;

            var origin = new POINT { X = 0, Y = 0 };
            ClientToScreen(hWnd, ref origin);
            return new Rectangle(origin.X, origin.Y, rect.Right - rect.Left, rect.Bottom - rect.Top);
        }
    }
}
