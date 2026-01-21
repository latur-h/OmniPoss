using System.Runtime.InteropServices;

namespace OmniPoss.Infrastructure.Interop
{
    internal static partial class NativeMethods
    {
        [LibraryImport("dnsapi", EntryPoint = "DnsFlushResolverCache")]
        internal static partial uint RefreshDNSCache();

        // Shutdown blocking APIs to request additional time from Windows during shutdown
        [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ShutdownBlockReasonCreate(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] string pwszReason);

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ShutdownBlockReasonDestroy(IntPtr hWnd);

        // Set process shutdown parameters to control shutdown priority
        // dwLevel: 0x280 (default) to 0x3FF (highest), higher = shutdown messages received earlier
        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool SetProcessShutdownParameters(uint dwLevel, uint dwFlags);

        // Shutdown parameter flags
        internal const uint SHUTDOWN_NORETRY = 0x00000001;

        // Post a message to a window's message queue (non-blocking)
        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    }
}
