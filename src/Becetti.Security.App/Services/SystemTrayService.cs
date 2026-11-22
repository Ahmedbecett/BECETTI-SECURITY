using System.Runtime.InteropServices;

namespace Becetti.Security.App.Services;

/// <summary>
/// Pure Win32 Windows Notification Area (System Tray) icon service using Shell_NotifyIconW.
/// Zero third-party dependencies. Supports left-click restore, right-click native quick menu,
/// live tooltip updates, and clean shutdown without leaving ghost tray icons.
/// </summary>
public sealed class SystemTrayService : IDisposable
{
    private const uint WM_USER = 0x0400;
    private const uint WM_TRAYICON = WM_USER + 42;
    private const uint WM_LBUTTONUP = 0x0202;
    private const uint WM_LBUTTONDBLCLK = 0x0203;
    private const uint WM_RBUTTONUP = 0x0205;
    private const uint WM_COMMAND = 0x0111;

    private const uint NIM_ADD = 0x00000000;
    private const uint NIM_MODIFY = 0x00000001;
    private const uint NIM_DELETE = 0x00000002;

    private const uint NIF_MESSAGE = 0x00000001;
    private const uint NIF_ICON = 0x00000002;
    private const uint NIF_TIP = 0x00000004;

    private const uint IMAGE_ICON = 1;
    private const uint LR_LOADFROMFILE = 0x00000010;
    private const uint LR_DEFAULTSIZE = 0x00000040;

    private const uint MF_STRING = 0x00000000;
    private const uint MF_SEPARATOR = 0x00000800;
    private const uint TPM_RIGHTBUTTON = 0x0002;
    private const uint TPM_RETURNCMD = 0x0100;

    private const int CmdOpen = 1001;
    private const int CmdYara = 1002;
    private const int CmdAdvanced = 1003;
    private const int CmdEdr = 1004;
    private const int CmdExit = 1099;

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    private WndProcDelegate? _wndProcDelegate;
    private IntPtr _hWnd;
    private IntPtr _hIcon;
    private bool _iconAdded;
    private bool _disposed;

    public event Action? OpenRequested;
    public event Action<string>? NavigateRequested;
    public event Action? ExitRequested;

    public bool Initialize(string tooltip = "BECETTI SECURITY — Active Protection")
    {
        if (!OperatingSystem.IsWindows() || _iconAdded)
            return _iconAdded;

        try
        {
            var className = "BecettiSecurityTrayWindow_" + Environment.ProcessId;
            _wndProcDelegate = WndProc;

            var wc = new WNDCLASSEXW
            {
                cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
                lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProcDelegate),
                hInstance = GetModuleHandleW(null),
                lpszClassName = className
            };
            RegisterClassExW(ref wc);

            _hWnd = CreateWindowExW(
                0, className, "BECETTI Tray Host", 0,
                0, 0, 0, 0,
                IntPtr.Zero, IntPtr.Zero, wc.hInstance, IntPtr.Zero);

            if (_hWnd == IntPtr.Zero)
                return false;

            var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "Logo.ico");
            if (File.Exists(iconPath))
            {
                _hIcon = LoadImageW(IntPtr.Zero, iconPath, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            }
            if (_hIcon == IntPtr.Zero)
            {
                _hIcon = LoadIconW(IntPtr.Zero, new IntPtr(32518)); // IDI_SHIELD
            }

            var nid = new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = _hWnd,
                uID = 1,
                uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage = WM_TRAYICON,
                hIcon = _hIcon,
                szTip = TruncateTip(tooltip)
            };

            _iconAdded = Shell_NotifyIconW(NIM_ADD, ref nid);
            return _iconAdded;
        }
        catch
        {
            return false;
        }
    }

    public void UpdateTooltip(string tooltip)
    {
        if (!_iconAdded || _hWnd == IntPtr.Zero) return;
        try
        {
            var nid = new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = _hWnd,
                uID = 1,
                uFlags = NIF_TIP,
                szTip = TruncateTip(tooltip)
            };
            Shell_NotifyIconW(NIM_MODIFY, ref nid);
        }
        catch { }
    }

    private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == WM_TRAYICON)
        {
            uint mouseMsg = (uint)(lParam.ToInt64() & 0xFFFF);
            if (mouseMsg is WM_LBUTTONUP or WM_LBUTTONDBLCLK)
            {
                OpenRequested?.Invoke();
                return IntPtr.Zero;
            }
            if (mouseMsg == WM_RBUTTONUP)
            {
                ShowContextMenu();
                return IntPtr.Zero;
            }
        }
        else if (msg == WM_COMMAND)
        {
            DispatchCommand((int)(wParam.ToInt64() & 0xFFFF));
            return IntPtr.Zero;
        }

        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    private void ShowContextMenu()
    {
        IntPtr hMenu = CreatePopupMenu();
        if (hMenu == IntPtr.Zero) return;

        try
        {
            AppendMenuW(hMenu, MF_STRING, new UIntPtr(CmdOpen), "Open BECETTI SECURITY");
            AppendMenuW(hMenu, MF_SEPARATOR, UIntPtr.Zero, null);
            AppendMenuW(hMenu, MF_STRING, new UIntPtr(CmdYara), "YARA Engine");
            AppendMenuW(hMenu, MF_STRING, new UIntPtr(CmdAdvanced), "Advanced Defense");
            AppendMenuW(hMenu, MF_STRING, new UIntPtr(CmdEdr), "EDR & Hardening");
            AppendMenuW(hMenu, MF_SEPARATOR, UIntPtr.Zero, null);
            AppendMenuW(hMenu, MF_STRING, new UIntPtr(CmdExit), "Exit BECETTI SECURITY");

            GetCursorPos(out var pt);
            SetForegroundWindow(_hWnd);
            uint cmd = TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.X, pt.Y, 0, _hWnd, IntPtr.Zero);
            if (cmd != 0)
                DispatchCommand((int)cmd);
        }
        finally
        {
            DestroyMenu(hMenu);
        }
    }

    private void DispatchCommand(int cmd)
    {
        switch (cmd)
        {
            case CmdOpen: OpenRequested?.Invoke(); break;
            case CmdYara: NavigateRequested?.Invoke("Yara"); break;
            case CmdAdvanced: NavigateRequested?.Invoke("AdvancedDefense"); break;
            case CmdEdr: NavigateRequested?.Invoke("EdrCenter"); break;
            case CmdExit: ExitRequested?.Invoke(); break;
        }
    }

    private static string TruncateTip(string tip) =>
        tip.Length > 120 ? tip[..120] : tip;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (_iconAdded && _hWnd != IntPtr.Zero)
            {
                var nid = new NOTIFYICONDATAW
                {
                    cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                    hWnd = _hWnd,
                    uID = 1
                };
                Shell_NotifyIconW(NIM_DELETE, ref nid);
                _iconAdded = false;
            }
            if (_hIcon != IntPtr.Zero)
            {
                DestroyIcon(_hIcon);
                _hIcon = IntPtr.Zero;
            }
            if (_hWnd != IntPtr.Zero)
            {
                DestroyWindow(_hWnd);
                _hWnd = IntPtr.Zero;
            }
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowExW(
        uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
        int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImageW(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadIconW(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, UIntPtr uIDNewItem, string? lpNewItem);

    [DllImport("user32.dll")]
    private static extern uint TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);
}
