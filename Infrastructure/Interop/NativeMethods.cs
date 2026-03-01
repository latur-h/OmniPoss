using System.Runtime.InteropServices;

namespace OmniPoss.Infrastructure.Interop
{
    internal enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER = 0,
        TCP_TABLE_BASIC_CONNECTIONS = 1,
        TCP_TABLE_BASIC_ALL = 2,
        TCP_TABLE_OWNER_PID_LISTENER = 3,
        TCP_TABLE_OWNER_PID_CONNECTIONS = 4,
        TCP_TABLE_OWNER_PID_ALL = 5,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    internal static partial class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = false)]
        internal static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref uint pdwOutBufLen,
            [MarshalAs(UnmanagedType.Bool)] bool sort,
            uint ulAf,
            TCP_TABLE_CLASS tableClass,
            uint reserved);

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
