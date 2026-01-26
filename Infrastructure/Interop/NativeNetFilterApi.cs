using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;

namespace OmniPoss.Infrastructure.Interop
{
    // NetFilterSDK v2.0 Native API Wrapper
    // Direct P/Invoke interface to nfapi.dll for NetFilterSDK communication

    internal static class NativeNetFilterApi
    {
        private const string NfApiDll = "nfapi"; // Use base name (Windows will find .dll)

        static NativeNetFilterApi()
        {
            // Ensure DLL can be found - try to load it explicitly from bin folder
            var binPath = Path.Combine(Environment.CurrentDirectory, "bin");
            var dllPath = Path.Combine(binPath, "nfapi.dll");
            if (File.Exists(dllPath))
            {
                // SetDllDirectory to help Windows find the DLL
                SetDllDirectory(binPath);
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        // Status codes
        public enum NF_STATUS
        {
            NF_STATUS_SUCCESS = 0,
            NF_STATUS_FAIL = -1,
            NF_STATUS_INVALID_ENDPOINT_ID = -2,
            NF_STATUS_NOT_INITIALIZED = -3,
            NF_STATUS_IO_ERROR = -4,
            NF_STATUS_REBOOT_REQUIRED = -5
        }

        // Direction
        public enum NF_DIRECTION
        {
            NF_D_IN = 1,
            NF_D_OUT = 2,
            NF_D_BOTH = 3
        }

        // Filtering flags
        [Flags]
        public enum NF_FILTERING_FLAG : uint
        {
            NF_ALLOW = 0,
            NF_BLOCK = 1,
            NF_FILTER = 2,
            NF_SUSPENDED = 4,
            NF_OFFLINE = 8,
            NF_INDICATE_CONNECT_REQUESTS = 16,
            NF_DISABLE_REDIRECT_PROTECTION = 32,
            NF_PEND_CONNECT_REQUEST = 64,
            NF_FILTER_AS_IP_PACKETS = 128,
            NF_READONLY = 256,
            NF_CONTROL_FLOW = 512,
            NF_REDIRECT = 1024,
            NF_BYPASS_IP_PACKETS = 2048
        }

        // Constants
        private const int NF_MAX_ADDRESS_LENGTH = 28;
        private const int NF_MAX_IP_ADDRESS_LENGTH = 16;
        private const int IPPROTO_TCP = 6;
        private const int IPPROTO_UDP = 17;
        private const int IPPROTO_ICMP = 1;
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        // Port range structure
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_PORT_RANGE
        {
            public ushort valueLow;
            public ushort valueHigh;
        }

        // IP packet options structure
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_IP_PACKET_OPTIONS
        {
            public ushort ip_family;          // AF_INET for IPv4 and AF_INET6 for IPv6
            public uint ipHeaderSize;         // Size in bytes of IP header
            public uint compartmentId;        // Network routing compartment identifier (can be zero)
            public uint interfaceIndex;       // Index of the interface on which the original packet data was received
            public uint subInterfaceIndex;    // Index of the subinterface on which the original packet data was received
            public uint flags;                // Can be a combination of flags from NF_IP_FLAG enumeration
        }

        // IP event handler structure (for ICMP filtering)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_IPEventHandler
        {
            public IntPtr ipReceive;
            public IntPtr ipSend;
        }

        // Rule structure with redirection support
        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        public struct NF_RULE_EX
        {
            public int protocol;
            public uint processId;
            public byte direction;
            public ushort localPort;
            public ushort remotePort;
            public ushort ip_family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_IP_ADDRESS_LENGTH)]
            public byte[] localIpAddress;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_IP_ADDRESS_LENGTH)]
            public byte[] localIpAddressMask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_IP_ADDRESS_LENGTH)]
            public byte[] remoteIpAddress;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_IP_ADDRESS_LENGTH)]
            public byte[] remoteIpAddressMask;

            public uint filteringFlag;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string processName;

            public NF_PORT_RANGE localPortRange;
            public NF_PORT_RANGE remotePortRange;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_ADDRESS_LENGTH)]
            public byte[] redirectTo;

            public uint localProxyProcessId;
        }

        // TCP connection info
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_TCP_CONN_INFO
        {
            public uint filteringFlag;
            public uint processId;
            public byte direction;
            public ushort ip_family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_ADDRESS_LENGTH)]
            public byte[] localAddress;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_ADDRESS_LENGTH)]
            public byte[] remoteAddress;

            public NF_TCP_CONN_INFO()
            {
                localAddress = new byte[NF_MAX_ADDRESS_LENGTH];
                remoteAddress = new byte[NF_MAX_ADDRESS_LENGTH];
            }
        }

        // UDP connection info
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_UDP_CONN_INFO
        {
            public uint filteringFlag;
            public uint processId;
            public ushort ip_family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_ADDRESS_LENGTH)]
            public byte[] localAddress;

            public NF_UDP_CONN_INFO()
            {
                localAddress = new byte[NF_MAX_ADDRESS_LENGTH];
            }
        }

        // UDP connection request
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_UDP_CONN_REQUEST
        {
            public uint filteringFlag;
            public uint processId;
            public ushort ip_family;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_ADDRESS_LENGTH)]
            public byte[] localAddress;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NF_MAX_ADDRESS_LENGTH)]
            public byte[] remoteAddress;

            public NF_UDP_CONN_REQUEST()
            {
                localAddress = new byte[NF_MAX_ADDRESS_LENGTH];
                remoteAddress = new byte[NF_MAX_ADDRESS_LENGTH];
            }
        }

        // UDP options structure
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_UDP_OPTIONS
        {
            public uint flags;
            public uint interfaceIndex;
            public uint subInterfaceIndex;
            public uint controlDataLength;
            public IntPtr controlData;
        }

        // Flow control statistics structure
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_FLOWCTL_STAT
        {
            public ulong bytesIn;
            public ulong bytesOut;
        }

        // Event handler structure (C API)
        // Pack = 1 ensures proper alignment for native code
        // Sequential layout matches the C structure exactly
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NF_EventHandler
        {
            public IntPtr threadStart;
            public IntPtr threadEnd;
            public IntPtr tcpConnectRequest;
            public IntPtr tcpConnected;
            public IntPtr tcpClosed;
            public IntPtr tcpReceive;
            public IntPtr tcpSend;
            public IntPtr tcpCanReceive;
            public IntPtr tcpCanSend;
            public IntPtr udpCreated;
            public IntPtr udpConnectRequest;
            public IntPtr udpClosed;
            public IntPtr udpReceive;
            public IntPtr udpSend;
            public IntPtr udpCanReceive;
            public IntPtr udpCanSend;
        }

        // API Functions
        [DllImport(NfApiDll, EntryPoint = "nf_init", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern NF_STATUS nf_init([MarshalAs(UnmanagedType.LPStr)] string driverName, IntPtr pHandler);

        [DllImport(NfApiDll, EntryPoint = "nf_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void nf_free();

        [DllImport(NfApiDll, EntryPoint = "nf_registerDriver", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern NF_STATUS nf_registerDriver([MarshalAs(UnmanagedType.LPStr)] string driverName);

        [DllImport(NfApiDll, EntryPoint = "nf_registerDriverEx", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern NF_STATUS nf_registerDriverEx([MarshalAs(UnmanagedType.LPStr)] string driverName, [MarshalAs(UnmanagedType.LPStr)] string driverPath);

        [DllImport(NfApiDll, EntryPoint = "nf_unRegisterDriver", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern NF_STATUS nf_unRegisterDriver([MarshalAs(UnmanagedType.LPStr)] string driverName);

        [DllImport(NfApiDll, EntryPoint = "nf_deleteRules", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_deleteRules();

        [DllImport(NfApiDll, EntryPoint = "nf_addRuleEx", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_addRuleEx(ref NF_RULE_EX pRule, int toHead);

        [DllImport(NfApiDll, EntryPoint = "nf_setRulesEx", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_setRulesEx(IntPtr pRules, int count);

        [DllImport(NfApiDll, EntryPoint = "nf_setOptions", CallingConvention = CallingConvention.Cdecl)]
        public static extern void nf_setOptions(uint nThreads, uint flags);

        [DllImport(NfApiDll, EntryPoint = "nf_adjustProcessPriviledges", CallingConvention = CallingConvention.Cdecl)]
        public static extern void nf_adjustProcessPriviledges();

        [DllImport(NfApiDll, EntryPoint = "nf_tcpPostReceive", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_tcpPostReceive(ulong id, IntPtr buf, int len);

        [DllImport(NfApiDll, EntryPoint = "nf_tcpPostSend", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_tcpPostSend(ulong id, IntPtr buf, int len);

        [DllImport(NfApiDll, EntryPoint = "nf_tcpSetConnectionState", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_tcpSetConnectionState(ulong id, int suspended);

        [DllImport(NfApiDll, EntryPoint = "nf_tcpClose", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_tcpClose(ulong id);

        [DllImport(NfApiDll, EntryPoint = "nf_udpPostReceive", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_udpPostReceive(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options);

        [DllImport(NfApiDll, EntryPoint = "nf_udpPostSend", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_udpPostSend(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options);

        // IP/ICMP filtering functions
        [DllImport(NfApiDll, EntryPoint = "nf_ipPostSend", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_ipPostSend(IntPtr buf, int len, IntPtr options);

        [DllImport(NfApiDll, EntryPoint = "nf_ipPostReceive", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_ipPostReceive(IntPtr buf, int len, IntPtr options);

        [DllImport(NfApiDll, EntryPoint = "nf_setIPEventHandler", CallingConvention = CallingConvention.Cdecl)]
        public static extern void nf_setIPEventHandler(IntPtr pHandler);

        // TCP additional functions
        [DllImport(NfApiDll, EntryPoint = "nf_getTCPConnInfo", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_getTCPConnInfo(ulong id, ref NF_TCP_CONN_INFO pConnInfo);

        [DllImport(NfApiDll, EntryPoint = "nf_completeTCPConnectRequest", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_completeTCPConnectRequest(ulong id, ref NF_TCP_CONN_INFO pConnInfo);

        [DllImport(NfApiDll, EntryPoint = "nf_findOriginalRemoteAddress", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_findOriginalRemoteAddress(ushort srcPort, IntPtr remoteAddress, int remoteAddressLen);

        [DllImport(NfApiDll, EntryPoint = "nf_tcpIsProxy", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool nf_tcpIsProxy(uint processId);

        [DllImport(NfApiDll, EntryPoint = "nf_tcpDisableFiltering", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_tcpDisableFiltering(ulong id);

        [DllImport(NfApiDll, EntryPoint = "nf_tcpSetSockOpt", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_tcpSetSockOpt(ulong id, int optname, IntPtr optval, int optlen);

        [DllImport(NfApiDll, EntryPoint = "nf_getTCPStat", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_getTCPStat(ulong id, ref NF_FLOWCTL_STAT pStat);

        // UDP additional functions
        [DllImport(NfApiDll, EntryPoint = "nf_getUDPConnInfo", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_getUDPConnInfo(ulong id, ref NF_UDP_CONN_INFO pConnInfo);

        [DllImport(NfApiDll, EntryPoint = "nf_udpSetConnectionState", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_udpSetConnectionState(ulong id, int suspended);

        [DllImport(NfApiDll, EntryPoint = "nf_udpDisableFiltering", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_udpDisableFiltering(ulong id);

        [DllImport(NfApiDll, EntryPoint = "nf_getUDPStat", CallingConvention = CallingConvention.Cdecl)]
        public static extern NF_STATUS nf_getUDPStat(ulong id, ref NF_FLOWCTL_STAT pStat);

        // Process name functions
        [DllImport(NfApiDll, EntryPoint = "nf_getProcessNameFromKernel", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool nf_getProcessNameFromKernel(uint processId, [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder buf, uint len);

        [DllImport(NfApiDll, EntryPoint = "nf_getProcessNameW", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool nf_getProcessNameW(uint processId, [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder buf, uint len);

        // Helper methods - Full WSA implementation
        /// <summary>
        /// Creates a sockaddr structure from IPAddress and port using WSA APIs for optimal performance.
        /// Uses WSAStringToAddress for robust address conversion.
        /// </summary>
        public static byte[] CreateSockAddr(IPAddress address, int port)
        {
            byte[] addrBytes = new byte[NF_MAX_ADDRESS_LENGTH];

            try
            {
                // Use WSA API for address conversion (more robust and efficient)
                string addressString = address.AddressFamily == AddressFamily.InterNetworkV6 
                    ? $"[{address}]:{port}" 
                    : $"{address}:{port}";
                
                int addressFamily = address.AddressFamily == AddressFamily.InterNetworkV6 ? AF_INET6 : AF_INET;
                int addrLen = NF_MAX_ADDRESS_LENGTH;
                
                unsafe
                {
                    fixed (byte* addrPtr = addrBytes)
                    {
                        IntPtr sockaddrPtr = new IntPtr(addrPtr);
                        int result = NativeMethods.WSAStringToAddressA(
                            addressString,
                            addressFamily,
                            IntPtr.Zero,
                            sockaddrPtr,
                            ref addrLen);

                        if (result == 0)
                        {
                            // Success - addrBytes now contains the sockaddr structure
                            return addrBytes;
                        }
                        else
                        {
                            // WSA conversion failed, fall back to manual construction
                            int error = NativeMethods.WSAGetLastError();
                            System.Diagnostics.Debug.WriteLine($"[WSA] WSAStringToAddress failed: {error}, falling back to manual construction");
                        }
                    }
                }
            }
            catch
            {
                // Fall through to manual construction
            }

            // Fallback: Manual construction (original implementation)
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                // IPv4 sockaddr_in
                var sin = new SockAddrIn
                {
                    sin_family = AF_INET,
                    sin_port = (ushort)IPAddress.HostToNetworkOrder((short)port),
                    sin_addr = BitConverter.ToUInt32(address.GetAddressBytes(), 0)
                };

                var sinBytes = StructToBytes(sin);
                Array.Copy(sinBytes, 0, addrBytes, 0, Math.Min(sinBytes.Length, addrBytes.Length));
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // IPv6 sockaddr_in6
                var sin6 = new SockAddrIn6
                {
                    sin6_family = AF_INET6,
                    sin6_port = (ushort)IPAddress.HostToNetworkOrder((short)port),
                    sin6_flowinfo = 0,
                    sin6_scope_id = 0
                };

                var addrBytes6 = address.GetAddressBytes();
                Array.Copy(addrBytes6, 0, sin6.sin6_addr, 0, 16);

                var sin6Bytes = StructToBytes(sin6);
                Array.Copy(sin6Bytes, 0, addrBytes, 0, Math.Min(sin6Bytes.Length, addrBytes.Length));
            }

            return addrBytes;
        }

        private static byte[] StructToBytes<T>(T structure) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            byte[] bytes = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(structure, ptr, false);
                Marshal.Copy(ptr, bytes, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
            return bytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct SockAddrIn
        {
            public ushort sin_family;
            public ushort sin_port;
            public uint sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;

            public SockAddrIn()
            {
                sin_zero = new byte[8];
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct SockAddrIn6
        {
            public ushort sin6_family;
            public ushort sin6_port;
            public uint sin6_flowinfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] sin6_addr;
            public uint sin6_scope_id;

            public SockAddrIn6()
            {
                sin6_addr = new byte[16];
            }
        }
    }
}
