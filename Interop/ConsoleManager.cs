using System.Runtime.InteropServices;

namespace OmniPoss.Interop
{
    internal static partial class ConsoleManager
    {
        public static bool IsEnabled { get; private set; } = false;

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool AllocConsole();

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool FreeConsole();

        [LibraryImport("kernel32.dll")]
        private static partial IntPtr GetConsoleWindow();

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;

        public static void InitConsole()
        {
            IntPtr handle = GetConsoleWindow();
            if (handle == IntPtr.Zero)
            {
                AllocConsole();
                ShowWindow(handle, SW_HIDE);
            }
        }

        public static void Show()
        {
            IntPtr handle = GetConsoleWindow();
            if (handle == IntPtr.Zero)
            {
                AllocConsole();
            }
            else
            {
                ShowWindow(handle, SW_SHOW);
            }

            IsEnabled = true;
        }

        public static void Hide()
        {
            IntPtr handle = GetConsoleWindow();
            if (handle != IntPtr.Zero)
            {
                ShowWindow(handle, SW_HIDE);
            }

            IsEnabled = false;
        }

        public static void Close()
        {
            FreeConsole();
        }
    }
}
