using System.Runtime.InteropServices;

namespace OmniPoss.Infrastructure.Interop
{
    internal static partial class NativeMethods
    {
        [LibraryImport("dnsapi", EntryPoint = "DnsFlushResolverCache")]
        internal static partial uint RefreshDNSCache();

        [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ShutdownBlockReasonCreate(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] string pwszReason);

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ShutdownBlockReasonDestroy(IntPtr hWnd);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool SetProcessShutdownParameters(uint dwLevel, uint dwFlags);

        internal const uint SHUTDOWN_NORETRY = 0x00000001;

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

        internal const int AF_INET = 2;
        internal const int AF_INET6 = 23;
        internal const int IPPROTO_IPV6 = 41;
        internal const int IPV6_V6ONLY = 27;


        [DllImport("ws2_32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        internal static extern int WSAStringToAddressA(
            [MarshalAs(UnmanagedType.LPStr)] string AddressString,
            int AddressFamily,
            IntPtr lpProtocolInfo,
            IntPtr lpAddress,
            ref int lpAddressLength);

        [DllImport("ws2_32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        internal static extern int WSAAddressToStringA(
            IntPtr lpsaAddress,
            int dwAddressLength,
            IntPtr lpProtocolInfo,
            System.Text.StringBuilder lpszAddressString,
            ref int lpdwAddressStringLength);

    }
}
