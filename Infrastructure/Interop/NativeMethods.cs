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

        // Winsock2 APIs for optimized connection establishment
        [LibraryImport("ws2_32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool WSAConnectByNameW(
            IntPtr s,
            [MarshalAs(UnmanagedType.LPWStr)] string nodename,
            [MarshalAs(UnmanagedType.LPWStr)] string servicename,
            ref uint localAddressLength,
            IntPtr localAddress,
            ref uint remoteAddressLength,
            IntPtr remoteAddress,
            IntPtr timeout,
            IntPtr reserved);

        [LibraryImport("ws2_32.dll", SetLastError = true)]
        internal static partial int WSAIoctl(
            IntPtr s,
            uint dwIoControlCode,
            IntPtr lpvInBuffer,
            uint cbInBuffer,
            IntPtr lpvOutBuffer,
            uint cbOutBuffer,
            out uint lpcbBytesReturned,
            IntPtr lpOverlapped,
            IntPtr lpCompletionRoutine);

        [LibraryImport("ws2_32.dll", SetLastError = true)]
        internal static partial int WSAGetLastError();

        // Socket option constants
        internal const int SO_UPDATE_CONNECT_CONTEXT = 0x7010; // From mswsock.h
        internal const int IPPROTO_IPV6 = 41;
        internal const int IPV6_V6ONLY = 27;
        internal const int SOL_SOCKET = 0xFFFF;
        internal const uint SIO_SET_SEND_RECEIVE_TIMEOUT = 0x98000004; // Custom IOCTL for setting send/receive timeouts

        // Timeout structure for WSAIoctl
        [StructLayout(LayoutKind.Sequential)]
        internal struct SEND_RECEIVE_TIMEOUT
        {
            public uint OnOff;
            public uint SendTimeout;
            public uint ReceiveTimeout;
        }

        // Timeval structure for WSAConnectByNameW timeout parameter
        [StructLayout(LayoutKind.Sequential)]
        internal struct Timeval
        {
            public int tv_sec;   // Seconds
            public int tv_usec;  // Microseconds
        }
    }
}
