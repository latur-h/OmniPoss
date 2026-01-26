using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using OmniPoss.Infrastructure.Interop;
using static OmniPoss.Infrastructure.Interop.NativeNetFilterApi;
using System.Diagnostics;
using System.Windows.Forms;
using System.Collections.Concurrent;
using System.Text;
using Serilog;
using System.Globalization;
using System.Threading;
using System.Buffers;
using static OmniPoss.Infrastructure.Interop.NativeMethods;

namespace OmniPoss.Interop
{
    /// <summary>
    /// Pure C# implementation of network traffic redirection using NetFilter SDK.
    /// Uses local TCP/UDP proxy servers (SocksRedirector pattern) that handle SOCKS5 protocol conversion.
    /// Directly interfaces with nfapi.dll via P/Invoke (no native wrapper library needed).
    /// Manages kernel driver callbacks, filtering rules, DNS handling, and connection redirection.
    /// </summary>
    internal partial class Redirector
    {
        private static string? _driverName;
        private static string? _targetHost;
        private static int _targetPort;
        private static string? _targetUser;
        private static string? _targetPass;
        private static uint _localProxyProcessId = 0;
        private static bool _isInitialized = false;
        private static IntPtr _eventHandlerPtr = IntPtr.Zero;
        private static IntPtr _ipEventHandlerPtr = IntPtr.Zero;

        private static bool _filterLoopback = false;
        private static bool _filterIntranet = true;
        private static bool _filterParent = false;
        private static bool _filterICMP = false;
        private static bool _filterTCP = true;
        private static bool _filterUDP = true;
        private static bool _filterDNS = false;
        private static bool _dnsOnly = false;
        private static bool _dnsProxy = false;
        private static string? _dnsHost;
        private static ushort _dnsPort = 53;
        private static int _icmpDelay = 0;


        private static LocalTcpProxy? _tcpProxy;
        private static LocalUdpProxy? _udpProxy;

        /// <summary>
        /// Connection lifecycle tracking for timing analysis.
        /// Tracks key events: ConnectRequest (redirect), Connected (NetFilter established), Accept (listener accepted).
        /// </summary>
        private class ConnectionLifecycle
        {
            public ulong ConnectionId { get; set; }
            public string CorrelationId { get; set; } = string.Empty;
            public long ConnectRequestTimestamp { get; set; }  // When redirect happens
            public long RedirectCompleteTimestamp { get; set; }  // When redirect completes
            public long? ConnectedTimestamp { get; set; }  // When NetFilterSDK considers connection established
            public long? AcceptStartTimestamp { get; set; }  // When accept() starts waiting
            public long? AcceptCompleteTimestamp { get; set; }  // When accept() returns
            public ushort LocalPort { get; set; }
        }

        private static readonly ConcurrentDictionary<ulong, ConnectionLifecycle> _connectionLifecycle = new();
        private static ushort _localProxyPort = 8888;

        // Cached local proxy addresses (avoid CreateSockAddr allocation per connection)
        private static byte[]? _cachedLocalProxyAddrV4 = null;
        private static byte[]? _cachedLocalProxyAddrV6 = null;
        private static ushort _cachedLocalProxyPort = 0;

        // Track original UDP destinations for redirected connections
        private static readonly ConcurrentDictionary<ulong, byte[]> _udpOriginalDestinations = new();

        private static readonly List<Delegate> _callbackDelegates = new();
        private static readonly List<GCHandle> _callbackHandles = new();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ThreadStartCallback();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ThreadEndCallback();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpConnectRequestCallback(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpConnectedCallback(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpClosedCallback(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpReceiveCallback(ulong id, IntPtr buf, int len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpSendCallback(ulong id, IntPtr buf, int len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpCanReceiveCallback(ulong id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void TcpCanSendCallback(ulong id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpCreatedCallback(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_INFO pConnInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpConnectRequestCallback(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_REQUEST pConnReq);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpClosedCallback(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_INFO pConnInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpReceiveCallback(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpSendCallback(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpCanReceiveCallback(ulong id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void UdpCanSendCallback(ulong id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void IpReceiveCallback(IntPtr buf, int len, IntPtr options);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void IpSendCallback(IntPtr buf, int len, IntPtr options);

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _icmpPacketTimes = new();
        private static readonly object _icmpDelayLock = new();

        /// <summary>
        /// Thread start callback stub. Provides valid function pointer for NetFilter SDK.
        /// </summary>
        private static void StubThreadStart() { }

        /// <summary>
        /// Thread end callback stub. Provides valid function pointer for NetFilter SDK.
        /// </summary>
        private static void StubThreadEnd() { }

        /// <summary>
        /// TCP connection request callback. Intercepts TCP connections, applies filtering rules,
        /// stores original destination info, and redirects to local proxy server.
        /// </summary>
        private static void StubTcpConnectRequest(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
            var callbackStartTime = Stopwatch.GetTimestamp();
            var correlationId = $"{id}-{callbackStartTime}";
            
            // Track connection lifecycle
            var lifecycle = new ConnectionLifecycle
            {
                ConnectionId = id,
                CorrelationId = correlationId,
                ConnectRequestTimestamp = callbackStartTime
            };
            _connectionLifecycle[id] = lifecycle;
            
            try
            {
                Log.Debug("[TCP-CALLBACK] Entry: ConnId={ConnectionId} CorrId={CorrelationId} Time={Timestamp}",
                    id, correlationId, callbackStartTime);
                
                if (_filterParent && pConnInfo.processId == Environment.ProcessId)
                {
                    Log.Debug("[TCP-CALLBACK] Bypass (filterParent): ConnId={ConnectionId}", id);
                    return;
                }

                try
                {
                    if (NativeNetFilterApi.nf_tcpIsProxy(pConnInfo.processId))
                    {
                        Log.Debug("[TCP-CALLBACK] Bypass (isProxy): ConnId={ConnectionId}", id);
                        return;
                    }
                }
                catch (EntryPointNotFoundException) { }
                catch (DllNotFoundException) { }

                // Fast private IP check - inline to avoid IPAddress object allocation
                // Note: Process name filtering is handled by NetFilterSDK kernel rules, no need to check here
                if (pConnInfo.ip_family == AF_INET && pConnInfo.remoteAddress.Length >= 8)
                {
                    byte firstByte = pConnInfo.remoteAddress[4];
                    if (firstByte == 10 || firstByte == 127 ||
                        (firstByte == 172 && pConnInfo.remoteAddress[5] >= 16 && pConnInfo.remoteAddress[5] <= 31) ||
                        (firstByte == 192 && pConnInfo.remoteAddress[5] == 168))
                    {
                        Log.Debug("[TCP-CALLBACK] Bypass (private IP): ConnId={ConnectionId}", id);
                        return;  // Private IP, bypass
                    }
                }
                else if (pConnInfo.ip_family == AF_INET6 && pConnInfo.remoteAddress.Length >= 24)
                {
                    // Fast IPv6 loopback check
                    bool isLoopback = true;
                    for (int i = 8; i < 16; i++)
                    {
                        if (pConnInfo.remoteAddress[i] != 0)
                        {
                            isLoopback = false;
                            break;
                        }
                    }
                    if (isLoopback && pConnInfo.remoteAddress[23] == 1)
                    {
                        Log.Debug("[TCP-CALLBACK] Bypass (IPv6 loopback): ConnId={ConnectionId}", id);
                        return;  // IPv6 loopback, bypass
                    }
                }

                if (_tcpProxy != null && _tcpProxy.IsInitialized)
                {
                    var localProxyPort = _tcpProxy.ListenPort;
                    
                    // Cache CreateSockAddr result (local proxy address doesn't change)
                    if (_cachedLocalProxyPort != localProxyPort || _cachedLocalProxyAddrV4 == null)
                    {
                        _cachedLocalProxyAddrV4 = NativeNetFilterApi.CreateSockAddr(IPAddress.Loopback, localProxyPort);
                        _cachedLocalProxyAddrV6 = NativeNetFilterApi.CreateSockAddr(IPAddress.IPv6Loopback, localProxyPort);
                        _cachedLocalProxyPort = localProxyPort;
                    }
                    
                    var localProxyAddr = pConnInfo.ip_family == AF_INET6 ? _cachedLocalProxyAddrV6! : _cachedLocalProxyAddrV4!;
                    var isIPv6 = pConnInfo.ip_family == AF_INET6;
                    
                    // Extract port (needed for connection info storage)
                    ushort extractedPort = 0;
                    var localAddr = pConnInfo.localAddress;
                    if (localAddr != null && localAddr.Length >= 4)
                    {
                        if (pConnInfo.ip_family == 2) // AF_INET
                        {
                            extractedPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(localAddr, 2));
                        }
                        else if (pConnInfo.ip_family == 23) // AF_INET6
                        {
                            extractedPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(localAddr, 2));
                        }
                    }
                    
                    // Save original addresses BEFORE modifying pConnInfo (copy directly to final arrays)
                    var originalRemoteAddr = new byte[NF_MAX_ADDRESS_LENGTH];
                    var originalLocalAddr = new byte[NF_MAX_ADDRESS_LENGTH];
                    Array.Copy(pConnInfo.remoteAddress, originalRemoteAddr, Math.Min(pConnInfo.remoteAddress.Length, NF_MAX_ADDRESS_LENGTH));
                    Array.Copy(pConnInfo.localAddress, originalLocalAddr, Math.Min(pConnInfo.localAddress.Length, NF_MAX_ADDRESS_LENGTH));

                    // Modify pConnInfo for redirect
                    Array.Copy(localProxyAddr, pConnInfo.remoteAddress, Math.Min(localProxyAddr.Length, pConnInfo.remoteAddress.Length));
                    pConnInfo.ip_family = (ushort)(isIPv6 ? AF_INET6 : AF_INET);
                    pConnInfo.processId = (uint)Environment.ProcessId;

                    // Create connInfoCopy with original addresses
                    var connInfoCopy = pConnInfo;
                    connInfoCopy.remoteAddress = originalRemoteAddr;
                    connInfoCopy.localAddress = originalLocalAddr;
                    
                    // Store connection info and log timing (focus on problematic spot)
                    var setConnInfoTime = Stopwatch.GetTimestamp();
                    _tcpProxy.SetConnInfo(connInfoCopy, id);
                    var callbackEndTime = Stopwatch.GetTimestamp();
                    var callbackDuration = (callbackEndTime - callbackStartTime) * 1000.0 / Stopwatch.Frequency;
                    
                    // Update lifecycle tracking
                    lifecycle.RedirectCompleteTimestamp = callbackEndTime;
                    lifecycle.LocalPort = extractedPort;
                    
                    Log.Debug("[TCP-CALLBACK] Redirect: ConnId={ConnectionId} Port={Port} Duration={DurationMs:F2}ms RedirectTo=127.0.0.1:{LocalProxyPort}",
                        id, extractedPort, callbackDuration, localProxyPort);
                }
                else
                {
                    QueueLog(() => Log.Warning("[TCP] Local proxy not initialized! Connection {ConnectionId}", id));
                }
            }
            catch (Exception ex)
            {
                var callbackEndTime = Stopwatch.GetTimestamp();
                var callbackDuration = (callbackEndTime - callbackStartTime) * 1000.0 / Stopwatch.Frequency;
                QueueLog(() => Log.Error(ex, "[TCP] TcpConnectRequest ERROR for connection {ConnectionId}: {Message} (Duration: {DurationMs:F2}ms)", 
                    id, ex.Message, callbackDuration));
            }
        }

        /// <summary>
        /// TCP connection established callback.
        /// Called by NetFilterSDK when the TCP connection is fully established (after SYN-ACK handshake).
        /// This is a critical timing point - it tells us when NetFilterSDK considers the connection ready.
        /// </summary>
        private static void StubTcpConnected(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
            var connectedTimestamp = Stopwatch.GetTimestamp();
            
            try
            {
                if (_connectionLifecycle.TryGetValue(id, out var lifecycle))
                {
                    lifecycle.ConnectedTimestamp = connectedTimestamp;
                    
                    // Calculate timing gaps
                    var redirectToConnected = (connectedTimestamp - lifecycle.RedirectCompleteTimestamp) * 1000.0 / Stopwatch.Frequency;
                    var totalFromRequest = (connectedTimestamp - lifecycle.ConnectRequestTimestamp) * 1000.0 / Stopwatch.Frequency;
                    
                    Log.Debug("[TCP-CONNECTED] ConnId={ConnectionId} CorrId={CorrelationId} Redirect→Connected={RedirectToConnectedMs:F2}ms Total={TotalMs:F2}ms",
                        id, lifecycle.CorrelationId, redirectToConnected, totalFromRequest);
                    
                    // If accept has already completed, log the timing relationship
                    if (lifecycle.AcceptCompleteTimestamp.HasValue)
                    {
                        var connectedToAccept = (lifecycle.AcceptCompleteTimestamp.Value - connectedTimestamp) * 1000.0 / Stopwatch.Frequency;
                        Log.Debug("[TCP-CONNECTED] ConnId={ConnectionId} Connected→Accept={ConnectedToAcceptMs:F2}ms (Accept happened {When})",
                            id, connectedToAccept, connectedToAccept < 0 ? "BEFORE Connected" : "AFTER Connected");
                    }
                }
                else
                {
                    Log.Debug("[TCP-CONNECTED] ConnId={ConnectionId} (no lifecycle tracking)", id);
                }
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[TCP] TcpConnected ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// TCP connection closed callback.
        /// </summary>
        private static void StubTcpClosed(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
            try
            {
                // Clean up lifecycle tracking
                if (_connectionLifecycle.TryRemove(id, out var lifecycle))
                {
                    var totalLifetime = 0.0;
                    if (lifecycle.AcceptCompleteTimestamp.HasValue)
                    {
                        var closeTimestamp = Stopwatch.GetTimestamp();
                        totalLifetime = (closeTimestamp - lifecycle.ConnectRequestTimestamp) * 1000.0 / Stopwatch.Frequency;
                    }
                    Log.Debug("[TCP-CLOSED] ConnId={ConnectionId} CorrId={CorrelationId} Lifetime={LifetimeMs:F2}ms",
                        id, lifecycle.CorrelationId, totalLifetime);
                }
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[TCP] TcpClosed ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// TCP receive callback. Posts received data back to NetFilter.
        /// </summary>
        private static void StubTcpReceive(ulong id, IntPtr buf, int len)
        {
            try
            {
                nf_tcpPostReceive(id, buf, len);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[TCP] TcpReceive ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// TCP send callback. Posts sent data back to NetFilter.
        /// </summary>
        private static void StubTcpSend(ulong id, IntPtr buf, int len)
        {
            try
            {
                nf_tcpPostSend(id, buf, len);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[TCP] TcpSend ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// TCP can receive callback stub. Provides valid function pointer for NetFilter SDK.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        private static void StubTcpCanReceive(ulong id) { }

        /// <summary>
        /// TCP can send callback stub. Provides valid function pointer for NetFilter SDK.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        private static void StubTcpCanSend(ulong id) { }

        /// <summary>
        /// UDP connection created callback. Applies filtering rules and process name matching.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="pConnInfo">Connection information.</param>
        private static void StubUdpCreated(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_INFO pConnInfo)
        {
            try
            {
                if (_filterParent && pConnInfo.processId == Environment.ProcessId)
                {
                    return;
                }

                // Note: Process name filtering is handled by NetFilterSDK kernel rules, no need to check here
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpCreated ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// UDP connect request callback.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="pConnReq">Connection request information.</param>
        private static void StubUdpConnectRequest(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_REQUEST pConnReq)
        {
        }

        /// <summary>
        /// UDP connection closed callback. Cleans up UDP proxy connection.
        /// </summary>
        private static void StubUdpClosed(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_INFO pConnInfo)
        {
            try
            {
                _udpProxy?.DeleteProxyConnection(id);
                _udpOriginalDestinations.TryRemove(id, out _);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpClosed ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// UDP receive callback. Posts received data back to NetFilter.
        /// </summary>
        private static void StubUdpReceive(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options)
        {
            try
            {
                NativeNetFilterApi.nf_udpPostReceive(id, remoteAddress, buf, len, options);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpReceive ERROR for connection {ConnectionId}", id));
            }
        }

        /// <summary>
        /// Creates an IPEndPoint from address bytes (sockaddr format) using WSA APIs for optimal performance.
        /// Uses WSAAddressToString for robust address parsing.
        /// </summary>
        private static IPEndPoint? CreateIPEndPointFromAddressBytes(byte[] addressBytes, ushort addrFamily)
        {
            if (addressBytes == null || addressBytes.Length < 8)
                return null;

            try
            {
                // Use WSA API for address conversion (more robust)
                int addressFamily = addrFamily == AF_INET6 ? NativeMethods.AF_INET6 : NativeMethods.AF_INET;
                int addrLen = Math.Min(addressBytes.Length, NF_MAX_ADDRESS_LENGTH);
                
                unsafe
                {
                    fixed (byte* addrPtr = addressBytes)
                    {
                        IntPtr sockaddrPtr = new IntPtr(addrPtr);
                        var sb = new System.Text.StringBuilder(64); // Enough for IPv6 with port
                        int sbLen = sb.Capacity;

                        int result = NativeMethods.WSAAddressToStringA(
                            sockaddrPtr,
                            addrLen,
                            IntPtr.Zero,
                            sb,
                            ref sbLen);

                        if (result == 0)
                        {
                            // Parse the address string (format: "ip:port" or "[ipv6]:port")
                            string addressString = sb.ToString();
                            // Try parsing as IPEndPoint format
                            int colonIndex = addressString.LastIndexOf(':');
                            if (colonIndex > 0)
                            {
                                string ipPart = addressString.Substring(0, colonIndex);
                                string portPart = addressString.Substring(colonIndex + 1);
                                
                                // Remove brackets from IPv6
                                if (ipPart.StartsWith("[") && ipPart.EndsWith("]"))
                                {
                                    ipPart = ipPart.Substring(1, ipPart.Length - 2);
                                }
                                
                                if (IPAddress.TryParse(ipPart, out IPAddress? ip) && 
                                    int.TryParse(portPart, out int port))
                                {
                                    return new IPEndPoint(ip, port);
                                }
                            }
                        }
                        else
                        {
                            // WSA conversion failed, fall back to manual parsing
                            int error = NativeMethods.WSAGetLastError();
                            System.Diagnostics.Debug.WriteLine($"[WSA] WSAAddressToString failed: {error}, falling back to manual parsing");
                        }
                    }
                }
            }
            catch
            {
                // Fall through to manual parsing
            }

            // Fallback: Manual parsing (original implementation)
            if (addrFamily == AF_INET && addressBytes.Length >= 8)
            {
                ushort port = BitConverter.ToUInt16(addressBytes, 2);
                port = (ushort)IPAddress.NetworkToHostOrder((short)port);
                uint ipAddr = BitConverter.ToUInt32(addressBytes, 4);
                return new IPEndPoint(new IPAddress(BitConverter.GetBytes(ipAddr)), port);
            }
            else if (addrFamily == AF_INET6 && addressBytes.Length >= 24)
            {
                ushort port = BitConverter.ToUInt16(addressBytes, 2);
                port = (ushort)IPAddress.NetworkToHostOrder((short)port);
                byte[] ipAddrBytes = new byte[16];
                Array.Copy(addressBytes, 8, ipAddrBytes, 0, 16);
                return new IPEndPoint(new IPAddress(ipAddrBytes), port);
            }
            return null;
        }

        /// <summary>
        /// UDP send callback. Handles DNS proxying and routes UDP packets through LocalUdpProxy.
        /// </summary>
        private static void StubUdpSend(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options)
        {
            try
            {
                byte[] remoteAddrBytes = new byte[NF_MAX_ADDRESS_LENGTH];
                Marshal.Copy(remoteAddress, remoteAddrBytes, 0, Math.Min(NF_MAX_ADDRESS_LENGTH, remoteAddrBytes.Length));

                ushort addrFamily = BitConverter.ToUInt16(remoteAddrBytes, 0);
                ushort remotePort = 0;
                bool isValidAddress = false;

                if (addrFamily == AF_INET && remoteAddrBytes.Length >= 8)
                {
                    remotePort = BitConverter.ToUInt16(remoteAddrBytes, 2);
                    remotePort = (ushort)IPAddress.NetworkToHostOrder((short)remotePort);
                    isValidAddress = true;
                }
                else if (addrFamily == AF_INET6 && remoteAddrBytes.Length >= 24)
                {
                    remotePort = BitConverter.ToUInt16(remoteAddrBytes, 2);
                    remotePort = (ushort)IPAddress.NetworkToHostOrder((short)remotePort);
                    isValidAddress = true;
                }

                // Fast private IP check (inline, no IPAddress allocation)
                if (isValidAddress)
                {
                    if (addrFamily == AF_INET && remoteAddrBytes.Length >= 8)
                    {
                        byte firstByte = remoteAddrBytes[4];
                        if (firstByte == 10 || firstByte == 127 ||
                            (firstByte == 172 && remoteAddrBytes[5] >= 16 && remoteAddrBytes[5] <= 31) ||
                            (firstByte == 192 && remoteAddrBytes[5] == 168))
                        {
                            // Private IP, bypass (unless DNS or redirected to proxy)
                            if (remotePort != 53 || !_filterDNS)
                            {
                                NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                                return;
                            }
                        }
                    }
                    else if (addrFamily == AF_INET6 && remoteAddrBytes.Length >= 24)
                    {
                        // Fast IPv6 loopback check
                        bool isLoopback = true;
                        for (int i = 8; i < 16; i++)
                        {
                            if (remoteAddrBytes[i] != 0)
                            {
                                isLoopback = false;
                                break;
                            }
                        }
                        if (isLoopback && remoteAddrBytes[23] == 1)
                        {
                            // IPv6 loopback, bypass (unless DNS or redirected to proxy)
                            if (remotePort != 53 || !_filterDNS)
                            {
                                NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                                return;
                            }
                        }
                    }
                }

                // DNS handling
                if (remotePort == 53 && _filterDNS)
                {
                    if (_dnsProxy && _udpProxy != null && isValidAddress)
                    {
                        var pool = ArrayPool<byte>.Shared;
                        var data = pool.Rent(len);
                        try
                        {
                            Marshal.Copy(buf, data, 0, len);
                            
                            // Create IPEndPoint only if needed for proxy
                            IPEndPoint? remoteEndPoint = null;
                            if (addrFamily == AF_INET && remoteAddrBytes.Length >= 8)
                            {
                                uint ipAddr = BitConverter.ToUInt32(remoteAddrBytes, 4);
                                remoteEndPoint = new IPEndPoint(new IPAddress(BitConverter.GetBytes(ipAddr)), remotePort);
                            }
                            else if (addrFamily == AF_INET6 && remoteAddrBytes.Length >= 24)
                            {
                                byte[] ipAddrBytes = new byte[16];
                                Array.Copy(remoteAddrBytes, 8, ipAddrBytes, 0, 16);
                                remoteEndPoint = new IPEndPoint(new IPAddress(ipAddrBytes), remotePort);
                            }
                            
                            if (remoteEndPoint != null && _udpProxy.UdpSend(id, data, len, remoteEndPoint, options, remoteAddress))
                            {
                                return;
                            }
                        }
                        finally
                        {
                            pool.Return(data);
                        }
                    }
                    else
                    {
                        NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                        return;
                    }
                }

                if (!isValidAddress)
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    return;
                }

                // Check if redirected to proxy (inline loopback check)
                bool isRedirectedToProxy = false;
                if (_tcpProxy != null && _tcpProxy.IsInitialized && _udpProxy != null)
                {
                    bool isLoopback = false;
                    if (addrFamily == AF_INET && remoteAddrBytes.Length >= 8)
                    {
                        isLoopback = remoteAddrBytes[4] == 127 && remoteAddrBytes[5] == 0 &&
                                     remoteAddrBytes[6] == 0 && remoteAddrBytes[7] == 1;
                    }
                    else if (addrFamily == AF_INET6 && remoteAddrBytes.Length >= 24)
                    {
                        isLoopback = true;
                        for (int i = 8; i < 16; i++)
                        {
                            if (remoteAddrBytes[i] != 0)
                            {
                                isLoopback = false;
                                break;
                            }
                        }
                        if (isLoopback && remoteAddrBytes[23] != 1) isLoopback = false;
                    }
                    bool portMatches = remotePort == _tcpProxy.ListenPort;
                    isRedirectedToProxy = isLoopback && portMatches;
                }

                // Redirect UDP connection to local proxy (if not already redirected)
                if (!isRedirectedToProxy && _tcpProxy != null && _tcpProxy.IsInitialized && _udpProxy != null)
                {
                    // Save original remote address BEFORE redirecting
                    var originalRemoteAddrBytes = new byte[NF_MAX_ADDRESS_LENGTH];
                    Array.Copy(remoteAddrBytes, originalRemoteAddrBytes, Math.Min(remoteAddrBytes.Length, NF_MAX_ADDRESS_LENGTH));
                    
                    // Get cached local proxy address
                    var localProxyPort = _tcpProxy.ListenPort;
                    if (_cachedLocalProxyPort != localProxyPort || _cachedLocalProxyAddrV4 == null)
                    {
                        _cachedLocalProxyAddrV4 = NativeNetFilterApi.CreateSockAddr(IPAddress.Loopback, localProxyPort);
                        _cachedLocalProxyAddrV6 = NativeNetFilterApi.CreateSockAddr(IPAddress.IPv6Loopback, localProxyPort);
                        _cachedLocalProxyPort = localProxyPort;
                    }
                    
                    var localProxyAddr = addrFamily == AF_INET6 ? _cachedLocalProxyAddrV6! : _cachedLocalProxyAddrV4!;
                    
                    // Create/ensure UDP proxy connection exists
                    if (!_udpProxy.CreateProxyConnection(id))
                    {
                        NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                        return;
                    }
                    
                    // Create IPEndPoint with ORIGINAL destination for proxy
                    var originalRemoteEndPoint = CreateIPEndPointFromAddressBytes(originalRemoteAddrBytes, addrFamily);
                    if (originalRemoteEndPoint == null)
                    {
                        NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                        return;
                    }
                    
                    // Store original destination for this connection
                    _udpOriginalDestinations[id] = originalRemoteAddrBytes;
                    
                    // Create IntPtr for original address (for proxy to store - only needed on first call)
                    IntPtr originalRemoteAddrPtr = Marshal.AllocHGlobal(NF_MAX_ADDRESS_LENGTH);
                    try
                    {
                        Marshal.Copy(originalRemoteAddrBytes, 0, originalRemoteAddrPtr, NF_MAX_ADDRESS_LENGTH);
                        
                        // Modify remoteAddress to redirect to local proxy (for NetFilter tracking)
                        Marshal.Copy(localProxyAddr, 0, remoteAddress, Math.Min(localProxyAddr.Length, NF_MAX_ADDRESS_LENGTH));
                        
                        // Send through proxy with ORIGINAL destination (proxy sends via SOCKS5)
                        var pool = ArrayPool<byte>.Shared;
                        var data = pool.Rent(len);
                        try
                        {
                            Marshal.Copy(buf, data, 0, len);
                            
                            // Proxy sends via SOCKS5 to original destination
                            if (_udpProxy.UdpSend(id, data, len, originalRemoteEndPoint, options, originalRemoteAddrPtr))
                            {
                                // Don't call nf_udpPostSend - proxy already sent it via SOCKS5
                                return;
                            }
                        }
                        finally
                        {
                            pool.Return(data);
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(originalRemoteAddrPtr);
                    }
                }
                else if (isRedirectedToProxy && _udpProxy != null)
                {
                    // Already redirected - get original destination from stored map
                    // Note: remoteAddrBytes is now the redirected address (local proxy), not original
                    if (_udpOriginalDestinations.TryGetValue(id, out var storedOriginalAddr))
                    {
                        // Create IPEndPoint with stored original destination
                        var originalRemoteEndPoint = CreateIPEndPointFromAddressBytes(storedOriginalAddr, BitConverter.ToUInt16(storedOriginalAddr, 0));
                        
                        if (originalRemoteEndPoint != null)
                        {
                            var pool = ArrayPool<byte>.Shared;
                            var data = pool.Rent(len);
                            try
                            {
                                Marshal.Copy(buf, data, 0, len);
                                
                                // Send through proxy with original destination
                                // OPTIMIZATION: Pass IntPtr.Zero since StoreOriginalRemoteAddress only stores once
                                // (checks _originalRemoteAddressBytes == null), so no need to allocate on every packet
                                if (_udpProxy.UdpSend(id, data, len, originalRemoteEndPoint, options, IntPtr.Zero))
                                {
                                    // Don't call nf_udpPostSend - proxy already sent it via SOCKS5
                                    return;
                                }
                            }
                            finally
                            {
                                pool.Return(data);
                            }
                        }
                    }
                    
                    // Fallback: post to NetFilter (proxy send failed or no stored original)
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    return;
                }

                NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpSend ERROR for connection {ConnectionId}", id));
                try
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                }
                catch { }
            }
        }
        /// <summary>
        /// UDP can receive callback stub. Provides valid function pointer for NetFilter SDK.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        private static void StubUdpCanReceive(ulong id) { }

        /// <summary>
        /// UDP can send callback stub. Provides valid function pointer for NetFilter SDK.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        private static void StubUdpCanSend(ulong id) { }

        /// <summary>
        /// IP receive callback. Handles ICMP packets with delay support and posts them back to the stack.
        /// </summary>
        /// <param name="buf">Pointer to IP packet buffer.</param>
        /// <param name="len">Packet length.</param>
        /// <param name="options">IP options pointer.</param>
        private static void StubIpReceive(IntPtr buf, int len, IntPtr options)
        {
            try
            {
                if (!_filterICMP || len < 20)
                    return;

                byte[] ipHeader = new byte[Math.Min(20, len)];
                Marshal.Copy(buf, ipHeader, 0, ipHeader.Length);

                if (ipHeader.Length >= 10 && ipHeader[9] == IPPROTO_ICMP)
                {
                    string packetKey = $"{BitConverter.ToUInt32(ipHeader, 12)}-{BitConverter.ToUInt32(ipHeader, 16)}";

                    if (_icmpDelay > 0)
                    {
                        lock (_icmpDelayLock)
                        {
                            if (_icmpPacketTimes.TryGetValue(packetKey, out var lastTime))
                            {
                                var elapsed = (DateTime.UtcNow - lastTime).TotalMilliseconds;
                                if (elapsed < _icmpDelay)
                                {
                                    return;
                                }
                            }
                            _icmpPacketTimes[packetKey] = DateTime.UtcNow;
                        }
                    }
                }

                NativeNetFilterApi.nf_ipPostReceive(buf, len, options);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[ICMP] IpReceive ERROR"));
            }
        }

        /// <summary>
        /// IP send callback. Handles ICMP packets with delay support and posts them back to the stack.
        /// </summary>
        /// <param name="buf">Pointer to IP packet buffer.</param>
        /// <param name="len">Packet length.</param>
        /// <param name="options">IP options pointer.</param>
        private static void StubIpSend(IntPtr buf, int len, IntPtr options)
        {
            try
            {
                if (!_filterICMP || len < 20)
                    return;

                byte[] ipHeader = new byte[Math.Min(20, len)];
                Marshal.Copy(buf, ipHeader, 0, ipHeader.Length);

                if (ipHeader.Length >= 10 && ipHeader[9] == IPPROTO_ICMP)
                {
                    string packetKey = $"{BitConverter.ToUInt32(ipHeader, 12)}-{BitConverter.ToUInt32(ipHeader, 16)}";

                    if (_icmpDelay > 0)
                    {
                        lock (_icmpDelayLock)
                        {
                            if (_icmpPacketTimes.TryGetValue(packetKey, out var lastTime))
                            {
                                var elapsed = (DateTime.UtcNow - lastTime).TotalMilliseconds;
                                if (elapsed < _icmpDelay)
                                {
                                    return;
                                }
                            }
                            _icmpPacketTimes[packetKey] = DateTime.UtcNow;
                        }
                    }
                }

                NativeNetFilterApi.nf_ipPostSend(buf, len, options);
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[ICMP] IpSend ERROR"));
            }
        }
        private static readonly List<string> _bypassPatterns = new();
        private static readonly List<string> _handlePatterns = new();

        private static readonly ConcurrentQueue<Action> _logQueue = new();
        private static readonly CancellationTokenSource _logQueueCts = new();
        private static Task? _logProcessorTask = null;
        private static readonly object _logProcessorLock = new();

        // Note: Process name filtering is handled by NetFilterSDK kernel rules (NF_RULE_EX.processName)
        // No need for callback-level process name lookups - kernel already filters based on rules


        private const int IPPROTO_TCP = 6;
        private const int IPPROTO_UDP = 17;
        private const int IPPROTO_ICMP = 1;
        private const int NF_MAX_IP_ADDRESS_LENGTH = 16;
        private const int NF_MAX_ADDRESS_LENGTH = 28;

        /// <summary>
        /// Checks if an IP address is a private/local network address that should bypass the proxy.
        /// </summary>
        /// <param name="address">IP address to check.</param>
        /// <returns>True if the address is private and should bypass the proxy.</returns>
        private static bool IsPrivateAddress(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = address.GetAddressBytes();
                if (bytes.Length == 4)
                {
                    if (bytes[0] == 10)
                        return true;
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                        return true;
                    if (bytes[0] == 192 && bytes[1] == 168)
                        return true;
                    if (bytes[0] == 127)
                        return true;
                }
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] bytes = address.GetAddressBytes();
                if (bytes.Length == 16)
                {
                    if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
                        bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
                        bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 &&
                        bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1)
                        return true;
                    if ((bytes[0] & 0xFE) == 0xFC)
                        return true;
                    if ((bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xC0) == 0x80)
                        return true;
                }
            }
            return false;
        }
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        private const byte SOCKS5_VERSION = 0x05;
        private const byte SOCKS5_CMD_CONNECT = 0x01;
        private const byte SOCKS5_CMD_UDP_ASSOCIATE = 0x03;
        private const byte SOCKS5_ATYP_IPV4 = 0x01;
        private const byte SOCKS5_ATYP_IPV6 = 0x04;
        private const byte SOCKS5_ATYP_DOMAIN = 0x03;

        public enum NameList
        {
            AIO_FILTERLOOPBACK,
            AIO_FILTERINTRANET,
            AIO_FILTERPARENT,
            AIO_FILTERICMP,
            AIO_FILTERTCP,
            AIO_FILTERUDP,
            AIO_FILTERDNS,
            AIO_ICMPING,
            AIO_DNSONLY,
            AIO_DNSPROX,
            AIO_DNSHOST,
            AIO_DNSPORT,
            AIO_TGTHOST,
            AIO_TGTPORT,
            AIO_TGTUSER,
            AIO_TGTPASS,
            AIO_TGTPROCESSID,
            AIO_LOCALPROXYPORT,
            AIO_CLRNAME,
            AIO_ADDNAME,
            AIO_BYPNAME
        }

        /// <summary>
        /// Sets a configuration value using a boolean parameter.
        /// </summary>
        /// <param name="name">Configuration name.</param>
        /// <param name="value">Boolean value to set.</param>
        /// <returns>True if the value was set successfully.</returns>
        public static bool Dial(NameList name, bool value)
        {
            return Dial(name, value.ToString().ToLower());
        }

        /// <summary>
        /// Sets a configuration value using a string parameter.
        /// </summary>
        /// <param name="name">Configuration name.</param>
        /// <param name="value">String value to set.</param>
        /// <returns>True if the value was set successfully.</returns>
        public static bool Dial(NameList name, string value)
        {
            switch (name)
            {
                case NameList.AIO_FILTERLOOPBACK:
                    return bool.TryParse(value, out _filterLoopback);
                case NameList.AIO_FILTERINTRANET:
                    return bool.TryParse(value, out _filterIntranet);
                case NameList.AIO_FILTERPARENT:
                    return bool.TryParse(value, out _filterParent);
                case NameList.AIO_FILTERICMP:
                    return bool.TryParse(value, out _filterICMP);
                case NameList.AIO_FILTERTCP:
                    return bool.TryParse(value, out _filterTCP);
                case NameList.AIO_FILTERUDP:
                    return bool.TryParse(value, out _filterUDP);
                case NameList.AIO_FILTERDNS:
                    return bool.TryParse(value, out _filterDNS);
                case NameList.AIO_DNSONLY:
                    return bool.TryParse(value, out _dnsOnly);
                case NameList.AIO_DNSPROX:
                    return bool.TryParse(value, out _dnsProxy);
                case NameList.AIO_DNSHOST:
                    _dnsHost = value;
                    return true;
                case NameList.AIO_DNSPORT:
                    return ushort.TryParse(value, out _dnsPort);
                case NameList.AIO_ICMPING:
                    return int.TryParse(value, out _icmpDelay);
                case NameList.AIO_TGTHOST:
                    _targetHost = value;
                    return true;
                case NameList.AIO_TGTPORT:
                    return int.TryParse(value, out _targetPort);
                case NameList.AIO_TGTPROCESSID:
                    return uint.TryParse(value, out _localProxyProcessId);
                case NameList.AIO_LOCALPROXYPORT:
                    return ushort.TryParse(value, out _localProxyPort);
                case NameList.AIO_TGTUSER:
                    _targetUser = value;
                    return true;
                case NameList.AIO_TGTPASS:
                    _targetPass = value;
                    return true;
                case NameList.AIO_CLRNAME:
                    _bypassPatterns.Clear();
                    _handlePatterns.Clear();
                    return true;
                case NameList.AIO_ADDNAME:
                    if (!string.IsNullOrEmpty(value))
                        _handlePatterns.Add(value);
                    return true;
                case NameList.AIO_BYPNAME:
                    if (!string.IsNullOrEmpty(value))
                        _bypassPatterns.Add(value);
                    return true;
                default:
                    return true;
            }
        }

        /// <summary>
        /// Initializes the NetFilter driver and sets up event handlers.
        /// </summary>
        /// <returns>Task that completes with true if initialization succeeded, false otherwise.</returns>
        public static Task<bool> InitAsync()
        {
            return Task.Run(() =>
            {
                var threadId = System.Threading.Thread.CurrentThread.ManagedThreadId;
                try
                {
                    if (_isInitialized)
                        return true;

                    if (string.IsNullOrEmpty(_driverName))
                        _driverName = "netfilter2";

                    try
                    {
                        nf_adjustProcessPriviledges();
                    }
                    catch (EntryPointNotFoundException) { }
                    catch (DllNotFoundException) { }

                    try
                    {
                        nf_setOptions(1, 0);
                    }
                    catch (EntryPointNotFoundException) { }
                    catch (DllNotFoundException) { }

                    var systemDriverFile = Path.Combine(Environment.SystemDirectory, "drivers", "netfilter2.sys");
                    if (!File.Exists(systemDriverFile))
                    {
                        throw new Exception($"Driver file not found at {systemDriverFile}. Please ensure the driver is installed first.");
                    }

                    NF_STATUS status;
                    var systemDriverPath = Path.Combine(Environment.SystemDirectory, "drivers");

                    try
                    {
                        try
                        {
                            nf_unRegisterDriver(_driverName);
                            System.Threading.Thread.Sleep(500);
                        }
                        catch (EntryPointNotFoundException) { }
                        catch { }

                        status = nf_registerDriverEx(_driverName, systemDriverPath);
                        if (status == NF_STATUS.NF_STATUS_SUCCESS || status == NF_STATUS.NF_STATUS_IO_ERROR)
                        {
                            System.Threading.Thread.Sleep(500);
                        }
                        else
                        {
                            status = nf_registerDriver(_driverName);
                            if (status == NF_STATUS.NF_STATUS_SUCCESS || status == NF_STATUS.NF_STATUS_IO_ERROR)
                            {
                                System.Threading.Thread.Sleep(500);
                            }
                        }
                    }
                    catch (EntryPointNotFoundException) { }
                    catch (DllNotFoundException)
                    {
                        throw new Exception("nfapi.dll not found");
                    }

                    try
                    {
                        NativeNetFilterApi.nf_adjustProcessPriviledges();
                    }
                    catch (EntryPointNotFoundException) { }
                    catch (DllNotFoundException) { }

                    _callbackDelegates.Clear();

                    var threadStart = new ThreadStartCallback(StubThreadStart);
                    var threadEnd = new ThreadEndCallback(StubThreadEnd);
                    var tcpConnectRequest = new TcpConnectRequestCallback(StubTcpConnectRequest);
                    var tcpConnected = new TcpConnectedCallback(StubTcpConnected);
                    var tcpClosed = new TcpClosedCallback(StubTcpClosed);
                    var tcpReceive = new TcpReceiveCallback(StubTcpReceive);
                    var tcpSend = new TcpSendCallback(StubTcpSend);
                    var tcpCanReceive = new TcpCanReceiveCallback(StubTcpCanReceive);
                    var tcpCanSend = new TcpCanSendCallback(StubTcpCanSend);
                    var udpCreated = new UdpCreatedCallback(StubUdpCreated);
                    var udpConnectRequest = new UdpConnectRequestCallback(StubUdpConnectRequest);
                    var udpClosed = new UdpClosedCallback(StubUdpClosed);
                    var udpReceive = new UdpReceiveCallback(StubUdpReceive);
                    var udpSend = new UdpSendCallback(StubUdpSend);
                    var udpCanReceive = new UdpCanReceiveCallback(StubUdpCanReceive);
                    var udpCanSend = new UdpCanSendCallback(StubUdpCanSend);

                    _callbackDelegates.Add(threadStart);
                    _callbackDelegates.Add(threadEnd);
                    _callbackDelegates.Add(tcpConnectRequest);
                    _callbackDelegates.Add(tcpConnected);
                    _callbackDelegates.Add(tcpClosed);
                    _callbackDelegates.Add(tcpReceive);
                    _callbackDelegates.Add(tcpSend);
                    _callbackDelegates.Add(tcpCanReceive);
                    _callbackDelegates.Add(tcpCanSend);
                    _callbackDelegates.Add(udpCreated);
                    _callbackDelegates.Add(udpConnectRequest);
                    _callbackDelegates.Add(udpClosed);
                    _callbackDelegates.Add(udpReceive);
                    _callbackDelegates.Add(udpSend);
                    _callbackDelegates.Add(udpCanReceive);
                    _callbackDelegates.Add(udpCanSend);

                    _callbackHandles.Add(GCHandle.Alloc(threadStart, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(threadEnd, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpConnectRequest, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpConnected, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpClosed, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpReceive, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpSend, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpCanReceive, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(tcpCanSend, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpCreated, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpConnectRequest, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpClosed, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpReceive, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpSend, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpCanReceive, GCHandleType.Normal));
                    _callbackHandles.Add(GCHandle.Alloc(udpCanSend, GCHandleType.Normal));

                    IntPtr ipEventHandlerPtr = IntPtr.Zero;
                    if (_filterICMP)
                    {
                        var ipReceive = new IpReceiveCallback(StubIpReceive);
                        var ipSend = new IpSendCallback(StubIpSend);
                        _callbackDelegates.Add(ipReceive);
                        _callbackDelegates.Add(ipSend);
                        _callbackHandles.Add(GCHandle.Alloc(ipReceive, GCHandleType.Normal));
                        _callbackHandles.Add(GCHandle.Alloc(ipSend, GCHandleType.Normal));

                        var ipEventHandler = new NativeNetFilterApi.NF_IPEventHandler
                        {
                            ipReceive = Marshal.GetFunctionPointerForDelegate(ipReceive),
                            ipSend = Marshal.GetFunctionPointerForDelegate(ipSend)
                        };

                        var ipEventHandlerSize = Marshal.SizeOf(typeof(NativeNetFilterApi.NF_IPEventHandler));
                        ipEventHandlerPtr = Marshal.AllocHGlobal(ipEventHandlerSize);
                        Marshal.StructureToPtr(ipEventHandler, ipEventHandlerPtr, true);
                    }

                    var eventHandler = new NativeNetFilterApi.NF_EventHandler
                    {
                        threadStart = Marshal.GetFunctionPointerForDelegate(threadStart),
                        threadEnd = Marshal.GetFunctionPointerForDelegate(threadEnd),
                        tcpConnectRequest = Marshal.GetFunctionPointerForDelegate(tcpConnectRequest),
                        tcpConnected = Marshal.GetFunctionPointerForDelegate(tcpConnected),
                        tcpClosed = Marshal.GetFunctionPointerForDelegate(tcpClosed),
                        tcpReceive = Marshal.GetFunctionPointerForDelegate(tcpReceive),
                        tcpSend = Marshal.GetFunctionPointerForDelegate(tcpSend),
                        tcpCanReceive = Marshal.GetFunctionPointerForDelegate(tcpCanReceive),
                        tcpCanSend = Marshal.GetFunctionPointerForDelegate(tcpCanSend),
                        udpCreated = Marshal.GetFunctionPointerForDelegate(udpCreated),
                        udpConnectRequest = Marshal.GetFunctionPointerForDelegate(udpConnectRequest),
                        udpClosed = Marshal.GetFunctionPointerForDelegate(udpClosed),
                        udpReceive = Marshal.GetFunctionPointerForDelegate(udpReceive),
                        udpSend = Marshal.GetFunctionPointerForDelegate(udpSend),
                        udpCanReceive = Marshal.GetFunctionPointerForDelegate(udpCanReceive),
                        udpCanSend = Marshal.GetFunctionPointerForDelegate(udpCanSend)
                    };

                    if (_eventHandlerPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(_eventHandlerPtr);
                        _eventHandlerPtr = IntPtr.Zero;
                    }

                    var eventHandlerSize = Marshal.SizeOf(typeof(NativeNetFilterApi.NF_EventHandler));
                    _eventHandlerPtr = Marshal.AllocHGlobal(eventHandlerSize);
                    Marshal.StructureToPtr(eventHandler, _eventHandlerPtr, true);
                    
                    // CRITICAL FIX: Initialize proxy servers BEFORE nf_init() to match C redirector behavior
                    // This ensures accept loop is running and ready when NetFilter callbacks activate
                    // Reference: Accept_Investigation.md - Solution 1: Fix Initialization Order
                    if (!string.IsNullOrEmpty(_targetHost) && _targetPort > 0)
                    {
                        try
                        {
                            var socks5Target = new IPEndPoint(IPAddress.Parse(_targetHost), _targetPort);

                            _tcpProxy = new LocalTcpProxy();
                            if (!_tcpProxy.Initialize(_localProxyPort, socks5Target, _targetUser, _targetPass))
                            {
                                throw new Exception("Failed to initialize local TCP proxy");
                            }
                            _localProxyPort = _tcpProxy.ListenPort;

                            _udpProxy = new LocalUdpProxy(socks5Target, _targetUser, _targetPass);

                            Log.Information("Local proxy servers initialized BEFORE nf_init(): TCP on port {TcpPort}, SOCKS5 target: {Socks5Target}",
                                _localProxyPort, socks5Target);
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex, "Failed to initialize local proxy servers");
                            throw new Exception($"Failed to initialize local proxy servers: {ex.Message}", ex);
                        }
                    }
                    else
                    {
                        Log.Warning("SOCKS5 target not configured - local proxy servers not initialized");
                    }
                    
                    if (Application.MessageLoop && Application.OpenForms.Count > 0)
                    {
                        NF_STATUS result = NF_STATUS.NF_STATUS_FAIL;
                        Exception? callException = null;

                        var form = Application.OpenForms[0];
                        if (form != null)
                        {
                            form.Invoke(new Action(() =>
                            {
                                try
                                {
                                    result = nf_init(_driverName, _eventHandlerPtr);
                                }
                                catch (Exception ex)
                                {
                                    callException = ex;
                                }
                            }));

                            if (callException != null)
                                throw callException;

                            status = result;
                        }
                        else
                        {
                            status = nf_init(_driverName, _eventHandlerPtr);
                        }
                    }
                    else
                    {
                        status = nf_init(_driverName, _eventHandlerPtr);
                    }

                    if (status == NF_STATUS.NF_STATUS_SUCCESS && _filterICMP && ipEventHandlerPtr != IntPtr.Zero)
                    {
                        try
                        {
                            NativeNetFilterApi.nf_setIPEventHandler(ipEventHandlerPtr);
                            _ipEventHandlerPtr = ipEventHandlerPtr;
                            Log.Information("ICMP/IP event handler registered (delay: {Delay}ms)", _icmpDelay);
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "Failed to set IP event handler - ICMP filtering may not work");
                        }
                    }
                    else if (ipEventHandlerPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(ipEventHandlerPtr);
                        ipEventHandlerPtr = IntPtr.Zero;
                    }

                    if (status != NF_STATUS.NF_STATUS_SUCCESS)
                    {
                        if (_eventHandlerPtr != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(_eventHandlerPtr);
                            _eventHandlerPtr = IntPtr.Zero;
                        }

                        var errorMsg = $"Failed to initialize NetFilter API with driver '{_driverName}': {status}";
                        if (status == NF_STATUS.NF_STATUS_FAIL)
                        {
                            errorMsg += ". This usually means the driver is not running or not properly registered.";
                        }
                        try
                        {
                            nf_unRegisterDriver(_driverName);
                        }
                        catch
                        {
                        }
                        throw new Exception(errorMsg);
                    }

                    try
                    {
                        ApplyRules();
                    }
                    catch (Exception ex)
                    {
                        if (_eventHandlerPtr != IntPtr.Zero)
                        {
                            try
                            {
                                nf_free();
                            }
                            catch
                            {
                            }
                            Marshal.FreeHGlobal(_eventHandlerPtr);
                            _eventHandlerPtr = IntPtr.Zero;
                        }
                        _tcpProxy?.Dispose();
                        _udpProxy?.Dispose();
                        throw new Exception($"Failed to apply filtering rules: {ex.Message}", ex);
                    }

                    StartLogProcessor();

                    _isInitialized = true;
                    return true;
                }
                catch (Exception ex)
                {
                    throw new Exception($"NetFilter initialization failed: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Frees the NetFilter driver and cleans up resources.
        /// </summary>
        /// <returns>Task that completes with true if cleanup succeeded, false otherwise.</returns>
        public static Task<bool> FreeAsync()
        {
            return Task.Run(() =>
            {
                try
                {
                    if (!_isInitialized)
                        return true;

                    nf_free();

                    if (_eventHandlerPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(_eventHandlerPtr);
                        _eventHandlerPtr = IntPtr.Zero;
                    }

                    if (_ipEventHandlerPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(_ipEventHandlerPtr);
                        _ipEventHandlerPtr = IntPtr.Zero;
                    }

                    if (!string.IsNullOrEmpty(_driverName))
                    {
                        try
                        {
                            nf_unRegisterDriver(_driverName);
                        }
                        catch
                        {
                        }
                    }

                    _tcpProxy?.Dispose();
                    _udpProxy?.Dispose();
                    _tcpProxy = null;
                    _udpProxy = null;

                    StopLogProcessor();

                    foreach (var handle in _callbackHandles)
                    {
                        if (handle.IsAllocated)
                        {
                            handle.Free();
                        }
                    }
                    _callbackHandles.Clear();
                    _callbackDelegates.Clear();

                    _isInitialized = false;
                    _bypassPatterns.Clear();
                    _handlePatterns.Clear();
                    return true;
                }
                catch
                {
                    return false;
                }
            });
        }

        /// <summary>
        /// Registers the driver name for NetFilter initialization.
        /// </summary>
        /// <param name="value">Driver name to register.</param>
        /// <returns>True if registration succeeded.</returns>
        public static bool aio_register(string value)
        {
            _driverName = value;
            return true;
        }


        /// <summary>
        /// Unregisters the NetFilter driver and frees resources.
        /// </summary>
        /// <param name="value">Driver name to unregister.</param>
        /// <returns>True if unregistration succeeded.</returns>
        public static bool aio_unregister(string value)
        {
            if (_isInitialized)
            {
                nf_free();
                try
                {
                    nf_unRegisterDriver(value);
                }
                catch (EntryPointNotFoundException)
                {
                }
                catch (DllNotFoundException)
                {
                }

                _isInitialized = false;
            }
            return true;
        }

        /// <summary>
        /// Applies filtering rules to the NetFilter driver based on current configuration.
        /// </summary>
        private static void ApplyRules()
        {
            nf_deleteRules();

            if (string.IsNullOrEmpty(_targetHost) || _targetPort <= 0)
            {
                Log.Warning("[Rules] Target not set! Host: '{TargetHost}', Port: {TargetPort}", _targetHost, _targetPort);
                return;
            }

            try
            {
                if (_tcpProxy == null || !_tcpProxy.IsInitialized)
                {
                    Log.Warning("[Rules] Local proxy not initialized! Cannot create redirect rules.");
                    return;
                }

                var localProxyPort = _tcpProxy.ListenPort;
                IPAddress localProxyIp = IPAddress.Loopback;
                var redirectAddr = NativeNetFilterApi.CreateSockAddr(localProxyIp, localProxyPort);
                var redirectAddrV6 = NativeNetFilterApi.CreateSockAddr(IPAddress.IPv6Loopback, localProxyPort);


                if (!_filterLoopback)
                {
                    var loopbackRuleV4 = CreateBypassRuleForNetwork(IPAddress.Parse("127.0.0.1"), IPAddress.Parse("255.0.0.0"), AF_INET, IPPROTO_TCP);
                    var loopbackRuleV4Copy = loopbackRuleV4;
                    nf_addRuleEx(ref loopbackRuleV4Copy, 1);

                    var loopbackRuleV6 = CreateBypassRuleForNetwork(IPAddress.IPv6Loopback, IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AF_INET6, IPPROTO_TCP);
                    var loopbackRuleV6Copy = loopbackRuleV6;
                    nf_addRuleEx(ref loopbackRuleV6Copy, 1);

                    var loopbackUdpRuleV4 = CreateBypassRuleForNetwork(IPAddress.Parse("127.0.0.1"), IPAddress.Parse("255.0.0.0"), AF_INET, IPPROTO_UDP);
                    var loopbackUdpRuleV4Copy = loopbackUdpRuleV4;
                    nf_addRuleEx(ref loopbackUdpRuleV4Copy, 1);

                    var loopbackUdpRuleV6 = CreateBypassRuleForNetwork(IPAddress.IPv6Loopback, IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AF_INET6, IPPROTO_UDP);
                    var loopbackUdpRuleV6Copy = loopbackUdpRuleV6;
                    nf_addRuleEx(ref loopbackUdpRuleV6Copy, 1);
                }

                if (!_filterIntranet)
                {
                    var intranetRanges = new[]
                    {
                        (IPAddress.Parse("10.0.0.0"), IPAddress.Parse("255.0.0.0")),
                        (IPAddress.Parse("100.64.0.0"), IPAddress.Parse("255.192.0.0")),
                        (IPAddress.Parse("169.254.0.0"), IPAddress.Parse("255.255.0.0")),
                        (IPAddress.Parse("100.64.0.0"), IPAddress.Parse("255.240.0.0")),
                        (IPAddress.Parse("192.0.0.0"), IPAddress.Parse("255.255.255.0")),
                        (IPAddress.Parse("192.168.0.0"), IPAddress.Parse("255.255.0.0")),
                        (IPAddress.Parse("198.18.0.0"), IPAddress.Parse("255.254.0.0"))
                    };

                    foreach (var (network, mask) in intranetRanges)
                    {
                        var intranetRuleV4 = CreateBypassRuleForNetwork(network, mask, AF_INET, IPPROTO_TCP);
                        var intranetRuleV4Copy = intranetRuleV4;
                        nf_addRuleEx(ref intranetRuleV4Copy, 1);

                        var intranetUdpRuleV4 = CreateBypassRuleForNetwork(network, mask, AF_INET, IPPROTO_UDP);
                        var intranetUdpRuleV4Copy = intranetUdpRuleV4;
                        nf_addRuleEx(ref intranetUdpRuleV4Copy, 1);
                    }
                }

                if (_filterICMP)
                {
                    var icmpRuleV4 = CreateIcmpRule(AF_INET);
                    var icmpRuleV4Copy = icmpRuleV4;
                    nf_addRuleEx(ref icmpRuleV4Copy, 0);

                    var icmpRuleV6 = CreateIcmpRule(AF_INET6);
                    var icmpRuleV6Copy = icmpRuleV6;
                    nf_addRuleEx(ref icmpRuleV6Copy, 0);
                }

                foreach (var pattern in _bypassPatterns)
                {
                    var bypassRuleV4 = CreateBypassRule(pattern, AF_INET, IPPROTO_TCP);
                    var bypassCopyV4 = bypassRuleV4;
                    nf_addRuleEx(ref bypassCopyV4, 1);

                    var bypassRuleV6 = CreateBypassRule(pattern, AF_INET6, IPPROTO_TCP);
                    var bypassCopyV6 = bypassRuleV6;
                    nf_addRuleEx(ref bypassCopyV6, 1);

                    var bypassUdpRuleV4 = CreateBypassRule(pattern, AF_INET, IPPROTO_UDP);
                    var bypassUdpCopyV4 = bypassUdpRuleV4;
                    nf_addRuleEx(ref bypassUdpCopyV4, 1);

                    var bypassUdpRuleV6 = CreateBypassRule(pattern, AF_INET6, IPPROTO_UDP);
                    var bypassUdpCopyV6 = bypassUdpRuleV6;
                    nf_addRuleEx(ref bypassUdpCopyV6, 1);
                }

                if (_handlePatterns.Count > 0)
                {
                    foreach (var pattern in _handlePatterns)
                    {
                        var handleRuleV4 = CreateHandleRule(pattern, redirectAddr, AF_INET, IPPROTO_TCP);
                        var handleCopyV4 = handleRuleV4;
                        nf_addRuleEx(ref handleCopyV4, 1);

                        var handleRuleV6 = CreateHandleRule(pattern, redirectAddrV6, AF_INET6, IPPROTO_TCP);
                        var handleCopyV6 = handleRuleV6;
                        nf_addRuleEx(ref handleCopyV6, 1);

                        var handleUdpRuleV4 = CreateHandleRule(pattern, redirectAddr, AF_INET, IPPROTO_UDP);
                        var handleUdpCopyV4 = handleUdpRuleV4;
                        nf_addRuleEx(ref handleUdpCopyV4, 1);

                        var handleUdpRuleV6 = CreateHandleRule(pattern, redirectAddrV6, AF_INET6, IPPROTO_UDP);
                        var handleUdpCopyV6 = handleUdpRuleV6;
                        nf_addRuleEx(ref handleUdpCopyV6, 1);

                    }
                }
                else
                {
                    var mainRuleV4 = CreateRedirectRule(redirectAddr, AF_INET, IPPROTO_TCP);
                    var ruleCopyV4 = mainRuleV4;
                    nf_addRuleEx(ref ruleCopyV4, 0);

                    var mainRuleV6 = CreateRedirectRule(redirectAddrV6, AF_INET6, IPPROTO_TCP);
                    var ruleCopyV6 = mainRuleV6;
                    nf_addRuleEx(ref ruleCopyV6, 0);

                    var mainUdpRuleV4 = CreateRedirectRule(redirectAddr, AF_INET, IPPROTO_UDP);
                    var udpRuleCopyV4 = mainUdpRuleV4;
                    nf_addRuleEx(ref udpRuleCopyV4, 0);

                    var mainUdpRuleV6 = CreateRedirectRule(redirectAddrV6, AF_INET6, IPPROTO_UDP);
                    var udpRuleCopyV6 = mainUdpRuleV6;
                    nf_addRuleEx(ref udpRuleCopyV6, 0);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[Rules] ERROR: Failed to apply rules: {Message}", ex.Message);
            }
        }

        /// <summary>
        /// Creates a redirect rule for the NetFilter driver.
        /// </summary>
        /// <param name="redirectAddr">Target address to redirect to.</param>
        /// <param name="ipFamily">IP address family (AF_INET or AF_INET6).</param>
        /// <param name="protocol">Protocol (IPPROTO_TCP or IPPROTO_UDP).</param>
        /// <returns>Configured NF_RULE_EX structure.</returns>
        private static NF_RULE_EX CreateRedirectRule(byte[] redirectAddr, int ipFamily, int protocol = IPPROTO_TCP)
        {
            uint filteringFlag;
            if (protocol == IPPROTO_TCP)
            {
                filteringFlag = (uint)(NF_FILTERING_FLAG.NF_FILTER | NF_FILTERING_FLAG.NF_INDICATE_CONNECT_REQUESTS | NF_FILTERING_FLAG.NF_CONTROL_FLOW | NF_FILTERING_FLAG.NF_DISABLE_REDIRECT_PROTECTION);
            }
            else
            {
                filteringFlag = (uint)(NF_FILTERING_FLAG.NF_FILTER | NF_FILTERING_FLAG.NF_REDIRECT | NF_FILTERING_FLAG.NF_INDICATE_CONNECT_REQUESTS | NF_FILTERING_FLAG.NF_CONTROL_FLOW | NF_FILTERING_FLAG.NF_DISABLE_REDIRECT_PROTECTION);
            }

            var rule = new NF_RULE_EX
            {
                protocol = (byte)protocol,
                processId = 0,
                direction = (byte)(protocol == IPPROTO_UDP ? NF_DIRECTION.NF_D_BOTH : NF_DIRECTION.NF_D_OUT),
                localPort = 0,
                remotePort = 0,
                ip_family = (ushort)ipFamily,
                localIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                localIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                filteringFlag = filteringFlag,
                processName = string.Empty,
                localPortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                remotePortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                redirectTo = new byte[NF_MAX_ADDRESS_LENGTH],
                localProxyProcessId = _localProxyProcessId
            };

            if (redirectAddr != null && redirectAddr.Length > 0)
            {
                Array.Copy(redirectAddr, 0, rule.redirectTo, 0, Math.Min(redirectAddr.Length, rule.redirectTo.Length));
            }

            return rule;
        }

        /// <summary>
        /// Creates a bypass rule for processes matching the specified pattern.
        /// </summary>
        /// <param name="processNamePattern">Process name pattern to match.</param>
        /// <param name="ipFamily">IP address family (AF_INET or AF_INET6).</param>
        /// <param name="protocol">Protocol (IPPROTO_TCP or IPPROTO_UDP).</param>
        /// <returns>Configured NF_RULE_EX structure.</returns>
        private static NF_RULE_EX CreateBypassRule(string processNamePattern, int ipFamily, int protocol = IPPROTO_TCP)
        {
            return new NF_RULE_EX
            {
                protocol = (byte)protocol,
                processId = 0,
                direction = (byte)NF_DIRECTION.NF_D_OUT,
                localPort = 0,
                remotePort = 0,
                ip_family = (ushort)ipFamily,
                localIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                localIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                filteringFlag = (uint)NF_FILTERING_FLAG.NF_ALLOW,
                processName = processNamePattern,
                localPortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                remotePortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                redirectTo = new byte[NF_MAX_ADDRESS_LENGTH],
                localProxyProcessId = 0
            };
        }

        /// <summary>
        /// Creates a bypass rule for a network range.
        /// </summary>
        /// <param name="network">Network address.</param>
        /// <param name="mask">Network mask.</param>
        /// <param name="ipFamily">IP address family (AF_INET or AF_INET6).</param>
        /// <param name="protocol">Protocol (IPPROTO_TCP or IPPROTO_UDP).</param>
        /// <returns>Configured NF_RULE_EX structure.</returns>
        private static NF_RULE_EX CreateBypassRuleForNetwork(IPAddress network, IPAddress mask, int ipFamily, int protocol = IPPROTO_TCP)
        {
            var rule = new NF_RULE_EX
            {
                protocol = (byte)protocol,
                processId = 0,
                direction = (byte)NF_DIRECTION.NF_D_OUT,
                localPort = 0,
                remotePort = 0,
                ip_family = (ushort)ipFamily,
                localIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                localIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                filteringFlag = (uint)NF_FILTERING_FLAG.NF_ALLOW,
                processName = string.Empty,
                localPortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                remotePortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                redirectTo = new byte[NF_MAX_ADDRESS_LENGTH],
                localProxyProcessId = 0
            };

            if (ipFamily == AF_INET && network.AddressFamily == AddressFamily.InterNetwork)
            {
                var networkBytes = network.GetAddressBytes();
                var maskBytes = mask.GetAddressBytes();
                Array.Copy(networkBytes, 0, rule.remoteIpAddress, 0, Math.Min(networkBytes.Length, NF_MAX_IP_ADDRESS_LENGTH));
                Array.Copy(maskBytes, 0, rule.remoteIpAddressMask, 0, Math.Min(maskBytes.Length, NF_MAX_IP_ADDRESS_LENGTH));
            }
            else if (ipFamily == AF_INET6 && network.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var networkBytes = network.GetAddressBytes();
                var maskBytes = mask.GetAddressBytes();
                Array.Copy(networkBytes, 0, rule.remoteIpAddress, 0, Math.Min(networkBytes.Length, NF_MAX_IP_ADDRESS_LENGTH));
                Array.Copy(maskBytes, 0, rule.remoteIpAddressMask, 0, Math.Min(maskBytes.Length, NF_MAX_IP_ADDRESS_LENGTH));
            }

            return rule;
        }

        /// <summary>
        /// Creates a handle rule for processes matching the specified pattern.
        /// NF driver matches process names at kernel level using tail matching.
        /// </summary>
        private static NF_RULE_EX CreateHandleRule(string processNamePattern, byte[] redirectAddr, int ipFamily, int protocol = IPPROTO_TCP)
        {
            var rule = CreateRedirectRule(redirectAddr, ipFamily, protocol);

            string nfPattern = processNamePattern;
            if (!nfPattern.StartsWith("*", StringComparison.Ordinal))
            {
                nfPattern = "*" + nfPattern;
            }
            rule.processName = nfPattern;
            return rule;
        }

        /// <summary>
        /// Creates an ICMP filtering rule.
        /// </summary>
        /// <param name="ipFamily">IP address family (AF_INET or AF_INET6).</param>
        /// <returns>Configured NF_RULE_EX structure.</returns>
        private static NF_RULE_EX CreateIcmpRule(int ipFamily)
        {
            return new NF_RULE_EX
            {
                protocol = IPPROTO_ICMP,
                processId = 0,
                direction = (byte)NF_DIRECTION.NF_D_BOTH,
                localPort = 0,
                remotePort = 0,
                ip_family = (ushort)ipFamily,
                localIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                localIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                filteringFlag = (uint)(NF_FILTERING_FLAG.NF_FILTER | NF_FILTERING_FLAG.NF_FILTER_AS_IP_PACKETS | NF_FILTERING_FLAG.NF_READONLY),
                processName = string.Empty,
                localPortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                remotePortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                redirectTo = new byte[NF_MAX_ADDRESS_LENGTH],
                localProxyProcessId = 0
            };
        }

        /// <summary>
        /// Starts the async log processor to handle deferred logging from callbacks.
        /// </summary>
        private static void StartLogProcessor()
        {
            lock (_logProcessorLock)
            {
                if (_logProcessorTask == null || _logProcessorTask.IsCompleted)
                {
                    _logProcessorTask = Task.Run(async () =>
                    {
                        while (!_logQueueCts.Token.IsCancellationRequested)
                        {
                            try
                            {
                                int processed = 0;
                                while (processed < 100 && _logQueue.TryDequeue(out var logAction))
                                {
                                    try
                                    {
                                        logAction();
                                    }
                                    catch { }
                                    processed++;
                                }

                                if (processed == 0)
                                {
                                    await Task.Delay(10, _logQueueCts.Token);
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                break;
                            }
                            catch { }
                        }

                        while (_logQueue.TryDequeue(out var logAction))
                        {
                            try
                            {
                                logAction();
                            }
                            catch { }
                        }
                    });
                }
            }
        }

        /// <summary>
        /// Stops the async log processor.
        /// </summary>
        private static void StopLogProcessor()
        {
            lock (_logProcessorLock)
            {
                _logQueueCts.Cancel();
                try
                {
                    _logProcessorTask?.Wait(TimeSpan.FromSeconds(2));
                }
                catch { }
                _logProcessorTask = null;
            }
        }

        /// <summary>
        /// Queues a log message for background processing to avoid blocking callbacks.
        /// </summary>
        /// <param name="logAction">Action that performs the logging operation.</param>
        private static void QueueLog(Action logAction)
        {
            if (_isInitialized)
            {
                _logQueue.Enqueue(logAction);
            }
            else
            {
                try
                {
                    logAction();
                }
                catch { }
            }
        }

        /// <summary>
        /// Maps NFConfig properties to Redirector.Dial calls for comprehensive configuration.
        /// </summary>
        /// <param name="config">NFConfig instance containing configuration values.</param>
        /// <exception cref="ArgumentNullException">Thrown when config is null.</exception>
        public static void ConfigureFromNFConfig(Configuration.NFConfig config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));


            Dial(NameList.AIO_FILTERLOOPBACK, config.FilterLoopback);
            Dial(NameList.AIO_FILTERINTRANET, config.FilterIntranet);

            if (config.FilterParent.HasValue)
                Dial(NameList.AIO_FILTERPARENT, config.FilterParent.Value);

            if (config.FilterTCP.HasValue)
                Dial(NameList.AIO_FILTERTCP, config.FilterTCP.Value);

            if (config.FilterUDP.HasValue)
                Dial(NameList.AIO_FILTERUDP, config.FilterUDP.Value);

            if (config.FilterDNS.HasValue)
                Dial(NameList.AIO_FILTERDNS, config.FilterDNS.Value);

            if (config.FilterICMP.HasValue)
                Dial(NameList.AIO_FILTERICMP, config.FilterICMP.Value);

            if (config.HandleOnlyDNS.HasValue)
                Dial(NameList.AIO_DNSONLY, config.HandleOnlyDNS.Value);

            if (config.DNSProxy.HasValue)
                Dial(NameList.AIO_DNSPROX, config.DNSProxy.Value);

            if (!string.IsNullOrEmpty(config.DNSHost))
            {
                try
                {
                    var dnsParts = config.DNSHost.Split(':');
                    var dnsHost = dnsParts[0];
                    var dnsPort = dnsParts.Length > 1 && ushort.TryParse(dnsParts[1], out var port) ? port : (ushort)53;

                    Dial(NameList.AIO_DNSHOST, dnsHost);
                    Dial(NameList.AIO_DNSPORT, dnsPort.ToString());
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[Config] Failed to parse DNSHost: {DnsHost}", config.DNSHost);
                }
            }

            if (config.ICMPDelay.HasValue)
            {
                Dial(NameList.AIO_ICMPING, config.ICMPDelay.Value.ToString());
            }

            if (config.LocalProxyPort.HasValue)
            {
                Dial(NameList.AIO_LOCALPROXYPORT, config.LocalProxyPort.Value.ToString());
            }

            Dial(NameList.AIO_CLRNAME, "");

            if (config.Bypass != null && config.Bypass.Count > 0)
            {
                foreach (var pattern in config.Bypass)
                {
                    if (!string.IsNullOrEmpty(pattern))
                    {
                        Dial(NameList.AIO_BYPNAME, pattern);
                    }
                }
            }

            if (config.Handle != null && config.Handle.Count > 0)
            {
                foreach (var pattern in config.Handle)
                {
                    if (!string.IsNullOrEmpty(pattern))
                    {
                        Dial(NameList.AIO_ADDNAME, pattern);
                    }
                }
            }
        }

        /// <summary>
        /// Updates accept timing for a connection in lifecycle tracking.
        /// Called from LocalTcpProxy when accept() completes.
        /// </summary>
        internal static void UpdateAcceptTiming(ulong netFilterConnectionId, long acceptStartTime, long acceptEndTime)
        {
            if (_connectionLifecycle.TryGetValue(netFilterConnectionId, out var lifecycle))
            {
                lifecycle.AcceptStartTimestamp = acceptStartTime;
                lifecycle.AcceptCompleteTimestamp = acceptEndTime;
                
                // Calculate timing gaps
                var redirectToAcceptStart = (acceptStartTime - lifecycle.RedirectCompleteTimestamp) * 1000.0 / Stopwatch.Frequency;
                var acceptWait = (acceptEndTime - acceptStartTime) * 1000.0 / Stopwatch.Frequency;
                
                // If Connected callback has fired, calculate that gap too
                if (lifecycle.ConnectedTimestamp.HasValue)
                {
                    var connectedToAcceptStart = (acceptStartTime - lifecycle.ConnectedTimestamp.Value) * 1000.0 / Stopwatch.Frequency;
                    Log.Debug("[ACCEPT-TIMING] ConnId={ConnectionId} Redirect→AcceptStart={RedirectToAcceptMs:F2}ms Connected→AcceptStart={ConnectedToAcceptMs:F2}ms AcceptWait={AcceptWaitMs:F2}ms",
                        netFilterConnectionId, redirectToAcceptStart, connectedToAcceptStart, acceptWait);
                }
                else
                {
                    Log.Debug("[ACCEPT-TIMING] ConnId={ConnectionId} Redirect→AcceptStart={RedirectToAcceptMs:F2}ms AcceptWait={AcceptWaitMs:F2}ms (Connected not yet fired)",
                        netFilterConnectionId, redirectToAcceptStart, acceptWait);
                }
            }
        }
    }
}
