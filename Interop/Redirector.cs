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
        private static uint _localProxyProcessId = 0; // Process ID of local SOCKS5 proxy (e.g., sing-box)
        private static bool _isInitialized = false;
        private static IntPtr _eventHandlerPtr = IntPtr.Zero;
        private static IntPtr _ipEventHandlerPtr = IntPtr.Zero;

        // Configuration flags (from Redirector.bin aio_dial)
        private static bool _filterLoopback = false; // AIO_FILTERLOOPBACK
        private static bool _filterIntranet = true; // AIO_FILTERINTRANET (default: true, filter intranet)
        private static bool _filterParent = false; // AIO_FILTERPARENT
        private static bool _filterICMP = false; // AIO_FILTERICMP
        private static bool _filterTCP = true; // AIO_FILTERTCP (default: true)
        private static bool _filterUDP = true; // AIO_FILTERUDP (default: true)
        private static bool _filterDNS = false; // AIO_FILTERDNS
        private static bool _dnsOnly = false; // AIO_DNSONLY
        private static bool _dnsProxy = false; // AIO_DNSPROX
        private static string? _dnsHost; // AIO_DNSHOST
        private static ushort _dnsPort = 53; // AIO_DNSPORT (default: 53)
        private static int _icmpDelay = 0; // AIO_ICMPING

        // Statistics tracking (from Redirector.bin aio_getUP/aio_getDL)
        private static long _uploadBytes = 0;
        private static long _downloadBytes = 0;
        private static readonly object _statsLock = new();

        // Local proxy servers (SocksRedirector pattern)
        private static LocalTcpProxy? _tcpProxy;
        private static LocalUdpProxy? _udpProxy;
        private static ushort _localProxyPort = 8888; // Default local proxy port

        // Stub callback delegates - must be kept alive to prevent GC
        // The driver calls these immediately after nf_init, so they must be valid function pointers
        private static readonly List<Delegate> _callbackDelegates = new();

        // Stub callback delegates - must match SDK signatures exactly
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

        // IP/ICMP event handler delegates
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void IpReceiveCallback(IntPtr buf, int len, IntPtr options);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void IpSendCallback(IntPtr buf, int len, IntPtr options);

        // ICMP delay tracking
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
            try
            {
                // Skip filtering for parent process if FilterParent is enabled
                if (_filterParent && pConnInfo.processId == Environment.ProcessId)
                {
                    return;
                }

                var processName = GetProcessName(pConnInfo.processId);
                Log.Information("[TCP] Connection intercepted: ID={ConnectionId}, Process={ProcessName} (PID={ProcessId}), IPFamily={IpFamily}",
                    id, processName, pConnInfo.processId, pConnInfo.ip_family);

                // Apply bypass/handle pattern matching
                if (CheckBypassName(pConnInfo.processId))
                {
                    return;
                }

                if (_filterTCP && !CheckHandleName(pConnInfo.processId))
                {
                    return;
                }

                // Extract original destination from connection info
                ushort originalPort = 0;
                IPAddress? originalIp = null;
                if (pConnInfo.ip_family == AF_INET)
                {
                    originalPort = BitConverter.ToUInt16(pConnInfo.remoteAddress, 2);
                    originalPort = (ushort)IPAddress.NetworkToHostOrder((short)originalPort);
                    uint ipAddr = BitConverter.ToUInt32(pConnInfo.remoteAddress, 4);
                    originalIp = new IPAddress(BitConverter.GetBytes(ipAddr));
                }
                else if (pConnInfo.ip_family == AF_INET6)
                {
                    originalPort = BitConverter.ToUInt16(pConnInfo.remoteAddress, 2);
                    originalPort = (ushort)IPAddress.NetworkToHostOrder((short)originalPort);
                    byte[] ipAddrBytes = new byte[16];
                    Array.Copy(pConnInfo.remoteAddress, 8, ipAddrBytes, 0, 16);
                    originalIp = new IPAddress(ipAddrBytes);
                }

                // Bypass private addresses (fallback if FilterLoopback/FilterIntranet didn't catch it)
                if (originalIp != null && IsPrivateAddress(originalIp))
                {
                    return;
                }

                // Store original connection info BEFORE modifying remoteAddress (critical for local proxy to retrieve destination)
                if (_tcpProxy != null)
                {
                    var connInfoCopy = pConnInfo;
                    connInfoCopy.remoteAddress = new byte[pConnInfo.remoteAddress.Length];
                    Array.Copy(pConnInfo.remoteAddress, connInfoCopy.remoteAddress, pConnInfo.remoteAddress.Length);
                    connInfoCopy.localAddress = new byte[pConnInfo.localAddress.Length];
                    Array.Copy(pConnInfo.localAddress, connInfoCopy.localAddress, pConnInfo.localAddress.Length);
                    _tcpProxy.SetConnInfo(connInfoCopy);
                }

                // Redirect connection to local proxy server (SocksRedirector pattern)
                if (_tcpProxy != null && _tcpProxy.IsInitialized)
                {
                    var localProxyPort = _tcpProxy.ListenPort;
                    IPAddress localProxyIp = pConnInfo.ip_family == AF_INET6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;

                    var localProxyAddr = NativeNetFilterApi.CreateSockAddr(localProxyIp, localProxyPort);
                    Array.Copy(localProxyAddr, pConnInfo.remoteAddress, Math.Min(localProxyAddr.Length, pConnInfo.remoteAddress.Length));
                    pConnInfo.ip_family = (ushort)(localProxyIp.AddressFamily == AddressFamily.InterNetworkV6 ? AF_INET6 : AF_INET);
                    pConnInfo.processId = (uint)Environment.ProcessId;

                    Log.Information("[TCP] Redirected to local proxy: Connection {ConnectionId}, {OriginalIp}:{OriginalPort} -> localhost:{LocalProxyPort}, Process={ProcessName}",
                        id, originalIp, originalPort, localProxyPort, processName);
                }
                else
                {
                    Log.Warning("[TCP] Local proxy not initialized! Connection {ConnectionId}", id);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[TCP] TcpConnectRequest ERROR for connection {ConnectionId}: {Message}", id, ex.Message);
            }
        }

        /// <summary>
        /// TCP connection established callback.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="pConnInfo">Connection information.</param>
        private static void StubTcpConnected(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
        }

        /// <summary>
        /// TCP connection closed callback.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="pConnInfo">Connection information.</param>
        private static void StubTcpClosed(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
        }

        /// <summary>
        /// TCP receive callback. Posts received data back to NetFilter and tracks download statistics.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="buf">Buffer containing received data.</param>
        /// <param name="len">Data length.</param>
        private static void StubTcpReceive(ulong id, IntPtr buf, int len)
        {
            try
            {
                nf_tcpPostReceive(id, buf, len);
                lock (_statsLock)
                {
                    _downloadBytes += len;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[TCP] TcpReceive ERROR for connection {ConnectionId}", id);
            }
        }

        /// <summary>
        /// TCP send callback. Posts sent data back to NetFilter and tracks upload statistics.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="buf">Buffer containing data to send.</param>
        /// <param name="len">Data length.</param>
        private static void StubTcpSend(ulong id, IntPtr buf, int len)
        {
            try
            {
                nf_tcpPostSend(id, buf, len);
                lock (_statsLock)
                {
                    _uploadBytes += len;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[TCP] TcpSend ERROR for connection {ConnectionId}", id);
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
                // FilterParent: Skip filtering for parent process (current process ID)
                if (_filterParent && pConnInfo.processId == Environment.ProcessId)
                {
                    Log.Debug("[UDP] Bypassing parent process: Connection {ConnectionId}, PID={ProcessId}", id, pConnInfo.processId);
                    return; // Don't redirect - rules should handle this, but return early for safety
                }

                // Runtime process name matching (like FUN_1800038d0 and FUN_180003ac0 in Redirector.bin)
                // Check bypass patterns first
                if (CheckBypassName(pConnInfo.processId))
                {
                    return; // Don't redirect - rules should handle this, but return early for safety
                }

                // Check handle patterns (if FilterUDP is enabled)
                if (_filterUDP && !CheckHandleName(pConnInfo.processId))
                {
                    return; // Don't redirect - rules should handle this, but return early for safety
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[UDP] UdpCreated ERROR for connection {ConnectionId}", id);
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
        /// <param name="id">Connection ID.</param>
        /// <param name="pConnInfo">Connection information.</param>
        private static void StubUdpClosed(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_INFO pConnInfo)
        {
            _udpProxy?.DeleteProxyConnection(id);
        }

        /// <summary>
        /// UDP receive callback. Posts received data back to NetFilter and tracks download statistics.
        /// </summary>
        /// <param name="id">Connection ID.</param>
        /// <param name="remoteAddress">Remote address sockaddr structure.</param>
        /// <param name="buf">Buffer containing received data.</param>
        /// <param name="len">Data length.</param>
        /// <param name="options">UDP options pointer.</param>
        private static void StubUdpReceive(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options)
        {
            try
            {
                NativeNetFilterApi.nf_udpPostReceive(id, remoteAddress, buf, len, options);
                lock (_statsLock)
                {
                    _downloadBytes += len;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[UDP] UdpReceive ERROR for connection {ConnectionId}", id);
            }
        }

        /// <summary>
        /// UDP send callback. Handles DNS proxying and routes UDP packets through LocalUdpProxy.
        /// </summary>
        private static void StubUdpSend(ulong id, IntPtr remoteAddress, IntPtr buf, int len, IntPtr options)
        {
            try
            {
                // Extract remote endpoint
                byte[] remoteAddrBytes = new byte[NF_MAX_ADDRESS_LENGTH];
                Marshal.Copy(remoteAddress, remoteAddrBytes, 0, Math.Min(NF_MAX_ADDRESS_LENGTH, remoteAddrBytes.Length));

                IPEndPoint? remoteEndPoint = null;
                ushort addrFamily = BitConverter.ToUInt16(remoteAddrBytes, 0);
                ushort remotePort = 0;

                if (addrFamily == AF_INET && remoteAddrBytes.Length >= 8)
                {
                    remotePort = BitConverter.ToUInt16(remoteAddrBytes, 2);
                    remotePort = (ushort)IPAddress.NetworkToHostOrder((short)remotePort);
                    uint ipAddr = BitConverter.ToUInt32(remoteAddrBytes, 4);
                    remoteEndPoint = new IPEndPoint(new IPAddress(BitConverter.GetBytes(ipAddr)), remotePort);
                }
                else if (addrFamily == AF_INET6 && remoteAddrBytes.Length >= 24)
                {
                    remotePort = BitConverter.ToUInt16(remoteAddrBytes, 2);
                    remotePort = (ushort)IPAddress.NetworkToHostOrder((short)remotePort);
                    byte[] ipAddrBytes = new byte[16];
                    Array.Copy(remoteAddrBytes, 8, ipAddrBytes, 0, 16);
                    remoteEndPoint = new IPEndPoint(new IPAddress(ipAddrBytes), remotePort);
                }

                // DNS special handling: proxy or bypass based on DNSProxy setting
                if (remotePort == 53 && _filterDNS)
                {
                    if (_dnsProxy && _udpProxy != null && remoteEndPoint != null)
                    {
                        byte[] data = new byte[len];
                        Marshal.Copy(buf, data, 0, len);
                        if (_udpProxy.UdpSend(id, data, len, remoteEndPoint, options, remoteAddress))
                        {
                            lock (_statsLock)
                            {
                                _uploadBytes += len;
                            }
                            return;
                        }
                    }
                    else
                    {
                        NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                        lock (_statsLock)
                        {
                            _uploadBytes += len;
                        }
                        return;
                    }
                }

                if (remoteEndPoint == null)
                {
                    Log.Warning("[UDP] Could not extract remote endpoint: Connection {ConnectionId}", id);
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    lock (_statsLock)
                    {
                        _uploadBytes += len;
                    }
                    return;
                }

                // Bypass private addresses
                if (IsPrivateAddress(remoteEndPoint.Address))
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    lock (_statsLock)
                    {
                        _uploadBytes += len;
                    }
                    return;
                }

                // Route through LocalUdpProxy (SOCKS5 UDP ASSOCIATE)
                if (_udpProxy != null)
                {
                    byte[] data = new byte[len];
                    Marshal.Copy(buf, data, 0, len);

                    if (_udpProxy.UdpSend(id, data, len, remoteEndPoint, options, remoteAddress))
                    {
                        lock (_statsLock)
                        {
                            _uploadBytes += len;
                        }
                        return;
                    }
                }

                // Fallback: direct send if proxy fails
                Log.Warning("[UDP] Proxy send failed, allowing direct send: Connection {ConnectionId}", id);
                NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                lock (_statsLock)
                {
                    _uploadBytes += len;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[UDP] UdpSend ERROR for connection {ConnectionId}", id);
                try
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    lock (_statsLock)
                    {
                        _uploadBytes += len;
                    }
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
                if (!_filterICMP || len < 20) // Minimum IP header size
                    return;

                // Parse IP header to check if it's ICMP
                byte[] ipHeader = new byte[Math.Min(20, len)];
                Marshal.Copy(buf, ipHeader, 0, ipHeader.Length);

                // Check protocol field (byte 9 in IP header)
                if (ipHeader.Length >= 10 && ipHeader[9] == IPPROTO_ICMP)
                {
                    // Extract source and destination IPs for delay tracking
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
                                    // Delay not met yet - drop packet
                                    return;
                                }
                            }
                            _icmpPacketTimes[packetKey] = DateTime.UtcNow;
                        }
                    }

                    // Track download statistics
                    lock (_statsLock)
                    {
                        _downloadBytes += len;
                    }
                }

                // Post the packet back to the stack
                NativeNetFilterApi.nf_ipPostReceive(buf, len, options);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[ICMP] IpReceive ERROR");
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
                if (!_filterICMP || len < 20) // Minimum IP header size
                    return;

                // Parse IP header to check if it's ICMP
                byte[] ipHeader = new byte[Math.Min(20, len)];
                Marshal.Copy(buf, ipHeader, 0, ipHeader.Length);

                // Check protocol field (byte 9 in IP header)
                if (ipHeader.Length >= 10 && ipHeader[9] == IPPROTO_ICMP)
                {
                    // Extract source and destination IPs for delay tracking
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
                                    // Delay not met yet - drop packet
                                    return;
                                }
                            }
                            _icmpPacketTimes[packetKey] = DateTime.UtcNow;
                        }
                    }

                    // Track upload statistics
                    lock (_statsLock)
                    {
                        _uploadBytes += len;
                    }
                }

                // Post the packet to the network
                NativeNetFilterApi.nf_ipPostSend(buf, len, options);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[ICMP] IpSend ERROR");
            }
        }
        private static readonly List<string> _bypassPatterns = new();
        private static readonly List<string> _handlePatterns = new();

        /// <summary>
        /// Gets process name from process ID for logging purposes.
        /// </summary>
        /// <param name="processId">Process ID.</param>
        /// <returns>Process name or "PID:{id}" if lookup fails.</returns>
        private static string GetProcessName(uint processId)
        {
            try
            {
                if (processId == 0) return "Unknown";
                var process = Process.GetProcessById((int)processId);
                // Process.ProcessName doesn't include .exe extension, but patterns might
                // Return the process name as-is (caller will handle .exe normalization)
                return process.ProcessName;
            }
            catch (ArgumentException)
            {
                // Process doesn't exist (might have exited)
                return $"PID:{processId}";
            }
            catch (Exception)
            {
                // Other errors (permission denied, etc.)
                return $"PID:{processId}";
            }
        }

        /// <summary>
        /// Gets full process path from process ID for pattern matching.
        /// </summary>
        /// <param name="processId">Process ID.</param>
        /// <returns>Full process path or "PID:{id}" if lookup fails.</returns>
        private static string GetProcessPath(uint processId)
        {
            try
            {
                if (processId == 0) return "Unknown";
                var process = Process.GetProcessById((int)processId);
                return process.MainModule?.FileName ?? process.ProcessName;
            }
            catch
            {
                return $"PID:{processId}";
            }
        }

        /// <summary>
        /// Checks if process matches handle patterns. Returns true if process should be redirected.
        /// If no patterns are configured, returns true (handle all processes).
        /// </summary>
        /// <param name="processId">Process ID to check.</param>
        /// <returns>True if process should be handled/redirected.</returns>
        private static bool CheckHandleName(uint processId)
        {
            if (_handlePatterns.Count == 0)
                return true; // No patterns = handle all processes

            var processName = GetProcessName(processId);
            var processPath = GetProcessPath(processId);

            foreach (var pattern in _handlePatterns)
            {
                if (string.IsNullOrEmpty(pattern))
                    continue;

                // Simple wildcard matching (supports * and ?)
                if (MatchesPattern(processName, pattern) || MatchesPattern(processPath, pattern))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if process matches bypass patterns. Returns true if process should bypass proxy.
        /// </summary>
        /// <param name="processId">Process ID to check.</param>
        /// <returns>True if process should be bypassed (not redirected).</returns>
        private static bool CheckBypassName(uint processId)
        {
            var processName = GetProcessName(processId);
            var processPath = GetProcessPath(processId);

            foreach (var pattern in _bypassPatterns)
            {
                if (string.IsNullOrEmpty(pattern))
                    continue;

                // Simple wildcard matching (supports * and ?)
                if (MatchesPattern(processName, pattern) || MatchesPattern(processPath, pattern))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Performs simple wildcard pattern matching (supports * and ?).
        /// Handles .exe extension normalization for process name matching.
        /// </summary>
        /// <param name="text">Text to match against.</param>
        /// <param name="pattern">Pattern with wildcards (* and ?).</param>
        /// <returns>True if text matches pattern.</returns>
        private static bool MatchesPattern(string text, string pattern)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(pattern))
                return false;

            // Convert to case-insensitive comparison
            text = text.ToLowerInvariant();
            pattern = pattern.ToLowerInvariant();

            // Normalize .exe extension: Process.ProcessName doesn't include .exe extension
            // If pattern ends with .exe but text doesn't, remove .exe from pattern for comparison
            if (pattern.EndsWith(".exe") && !text.EndsWith(".exe"))
            {
                pattern = pattern.Substring(0, pattern.Length - 4); // Remove .exe
            }
            // If text has .exe but pattern doesn't, remove .exe from text for comparison
            else if (text.EndsWith(".exe") && !pattern.EndsWith(".exe"))
            {
                text = text.Substring(0, text.Length - 4); // Remove .exe
            }

            // Simple wildcard implementation
            int textIndex = 0;
            int patternIndex = 0;
            int textStar = -1;
            int patternStar = -1;

            while (textIndex < text.Length)
            {
                if (patternIndex < pattern.Length && (pattern[patternIndex] == '?' || pattern[patternIndex] == text[textIndex]))
                {
                    textIndex++;
                    patternIndex++;
                }
                else if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
                {
                    textStar = textIndex;
                    patternStar = patternIndex;
                    patternIndex++;
                }
                else if (patternStar != -1)
                {
                    textStar++;
                    textIndex = textStar;
                    patternIndex = patternStar + 1;
                }
                else
                {
                    return false;
                }
            }

            while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
                patternIndex++;

            return patternIndex == pattern.Length;
        }

        /// <summary>
        /// Extracts IP address from sockaddr structure for logging purposes.
        /// </summary>
        /// <param name="sockAddr">sockaddr structure bytes.</param>
        /// <returns>IP address string or "Unknown" if extraction fails.</returns>
        private static string ExtractIpFromSockAddr(byte[] sockAddr)
        {
            try
            {
                if (sockAddr == null || sockAddr.Length < 2) return "Unknown";
                ushort family = BitConverter.ToUInt16(sockAddr, 0);
                if (family == AF_INET && sockAddr.Length >= 8)
                {
                    uint ipAddr = BitConverter.ToUInt32(sockAddr, 4);
                    return new IPAddress(BitConverter.GetBytes(ipAddr)).ToString();
                }
                else if (family == AF_INET6 && sockAddr.Length >= 24)
                {
                    byte[] ipAddrBytes = new byte[16];
                    Array.Copy(sockAddr, 8, ipAddrBytes, 0, 16);
                    return new IPAddress(ipAddrBytes).ToString();
                }
            }
            catch { }
            return "Unknown";
        }

        // Constants
        private const int IPPROTO_TCP = 6;
        private const int IPPROTO_UDP = 17;
        private const int IPPROTO_ICMP = 1;
        private const int NF_MAX_IP_ADDRESS_LENGTH = 16;
        private const int NF_MAX_ADDRESS_LENGTH = 28;

        /// <summary>
        /// Checks if an IP address is a private/local network address that should bypass the proxy.
        /// </summary>
        private static bool IsPrivateAddress(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                // IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 (loopback)
                byte[] bytes = address.GetAddressBytes();
                if (bytes.Length == 4)
                {
                    // 10.0.0.0/8
                    if (bytes[0] == 10)
                        return true;
                    // 172.16.0.0/12
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                        return true;
                    // 192.168.0.0/16
                    if (bytes[0] == 192 && bytes[1] == 168)
                        return true;
                    // 127.0.0.0/8 (loopback)
                    if (bytes[0] == 127)
                        return true;
                }
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // IPv6: ::1/128 (loopback), fc00::/7 (unique local), fe80::/10 (link-local)
                byte[] bytes = address.GetAddressBytes();
                if (bytes.Length == 16)
                {
                    // ::1 (loopback)
                    if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
                        bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
                        bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 &&
                        bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1)
                        return true;
                    // fc00::/7 (unique local address)
                    if ((bytes[0] & 0xFE) == 0xFC)
                        return true;
                    // fe80::/10 (link-local address)
                    if ((bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xC0) == 0x80)
                        return true;
                }
            }
            return false;
        }
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        // SOCKS5 protocol constants
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
            AIO_TGTPROCESSID, // Process ID of local SOCKS5 proxy
            AIO_LOCALPROXYPORT, // Local proxy server port (default: 8888)
            AIO_CLRNAME,
            AIO_ADDNAME,
            AIO_BYPNAME
        }

        public static bool Dial(NameList name, bool value)
        {
            return Dial(name, value.ToString().ToLower());
        }

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
                    // Set local proxy process ID to prevent redirect protection from blocking local connections
                    return uint.TryParse(value, out _localProxyProcessId);
                case NameList.AIO_LOCALPROXYPORT:
                    // Set local proxy server port (default: 8888)
                    // Must be set before InitAsync() is called
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

        public static Task<bool> InitAsync()
        {
            // CRITICAL: nf_init might need to be called from the main thread
            // The samples call it directly from Main(), not from a background task
            // For testing: Try calling nf_init synchronously on the current thread
            // If we're on a background thread, we'll need to marshal to UI thread
            return Task.Run(() =>
            {
                var threadId = System.Threading.Thread.CurrentThread.ManagedThreadId;
                try
                {
                    if (_isInitialized)
                        return true;

                    if (string.IsNullOrEmpty(_driverName))
                        _driverName = "netfilter2";

                    // Adjust process privileges (required for process name access)
                    // Must be called before nf_init according to documentation
                    // This function may not be available in all SDK versions
                    try
                    {
                        nf_adjustProcessPriviledges();
                    }
                    catch (EntryPointNotFoundException)
                    {
                        // Function not available in this SDK version - continue without it
                        // Process name access may be limited but basic functionality should work
                    }
                    catch (DllNotFoundException)
                    {
                        // DLL not found - skip
                    }

                    // Set options before initialization (default: 1 thread, no flags)
                    // Must be called before nf_init according to documentation
                    // This function may not be available in all SDK versions
                    try
                    {
                        nf_setOptions(1, 0);
                    }
                    catch (EntryPointNotFoundException)
                    {
                        // Function not available in this SDK version - continue with defaults
                        // Default values (1 thread, no flags) will be used
                    }
                    catch (DllNotFoundException)
                    {
                        // DLL not found - skip
                    }

                    // Register the driver with the API
                    // First, ensure the driver file exists in the system directory
                    var systemDriverFile = Path.Combine(Environment.SystemDirectory, "drivers", "netfilter2.sys");
                    if (!File.Exists(systemDriverFile))
                    {
                        throw new Exception($"Driver file not found at {systemDriverFile}. Please ensure the driver is installed first.");
                    }

                    // According to SDK samples, nf_init can be called directly without nf_registerDriver
                    // if the driver is already installed and registered via nfregdrv.exe (which we do in NetworkFilterDriver)
                    // However, we'll try to register it via API as well for compatibility
                    NF_STATUS status;
                    var systemDriverPath = Path.Combine(Environment.SystemDirectory, "drivers");

                    try
                    {
                        // Try to unregister first to clear any old registration
                        try
                        {
                            nf_unRegisterDriver(_driverName);
                            System.Threading.Thread.Sleep(500);
                        }
                        catch (EntryPointNotFoundException)
                        {
                            // Function not available - continue
                        }
                        catch
                        {
                            // Ignore unregister errors - driver might not be registered
                        }

                        // Try nf_registerDriverEx with the driver directory path
                        status = nf_registerDriverEx(_driverName, systemDriverPath);
                        if (status == NF_STATUS.NF_STATUS_SUCCESS || status == NF_STATUS.NF_STATUS_IO_ERROR)
                        {
                            // Success or already registered - both are OK
                            System.Threading.Thread.Sleep(500);
                        }
                        else
                        {
                            // If that fails, try nf_registerDriver without path
                            status = nf_registerDriver(_driverName);
                            if (status == NF_STATUS.NF_STATUS_SUCCESS || status == NF_STATUS.NF_STATUS_IO_ERROR)
                            {
                                // Success or already registered
                                System.Threading.Thread.Sleep(500);
                            }
                            else
                            {
                                // Both failed, but we'll continue anyway - driver might be registered via nfregdrv.exe
                                // According to samples, nf_init can work even if registration fails
                            }
                        }
                    }
                    catch (EntryPointNotFoundException)
                    {
                        // Functions not available - driver may already be registered as Windows service
                        // Continue with initialization
                    }
                    catch (DllNotFoundException)
                    {
                        // DLL not found - this is a critical error
                        throw new Exception("nfapi.dll not found");
                    }

                    // Initialize NetFilter API
                    // According to samples, we must call nf_adjustProcessPriviledges() BEFORE nf_init
                    // This adjusts process privileges required for the driver
                    try
                    {
                        NativeNetFilterApi.nf_adjustProcessPriviledges();
                    }
                    catch (EntryPointNotFoundException)
                    {
                        // Function may not be available in all SDK versions - continue
                    }
                    catch (DllNotFoundException)
                    {
                        // DLL not found - skip
                    }

                    // CRITICAL FIX: The driver calls threadStart() immediately after nf_init
                    // We must provide valid function pointers, not IntPtr.Zero
                    // Create stub callback delegates and get their function pointers
                    _callbackDelegates.Clear(); // Clear old delegates if re-initializing

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

                    // Keep delegates alive to prevent GC
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

                    // Create IP/ICMP event handler delegates if ICMP filtering is enabled
                    IntPtr ipEventHandlerPtr = IntPtr.Zero;
                    if (_filterICMP)
                    {
                        var ipReceive = new IpReceiveCallback(StubIpReceive);
                        var ipSend = new IpSendCallback(StubIpSend);
                        _callbackDelegates.Add(ipReceive);
                        _callbackDelegates.Add(ipSend);

                        var ipEventHandler = new NativeNetFilterApi.NF_IPEventHandler
                        {
                            ipReceive = Marshal.GetFunctionPointerForDelegate(ipReceive),
                            ipSend = Marshal.GetFunctionPointerForDelegate(ipSend)
                        };

                        var ipEventHandlerSize = Marshal.SizeOf(typeof(NativeNetFilterApi.NF_IPEventHandler));
                        ipEventHandlerPtr = Marshal.AllocHGlobal(ipEventHandlerSize);
                        Marshal.StructureToPtr(ipEventHandler, ipEventHandlerPtr, true);
                    }

                    // Create event handler structure with valid function pointers
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

                    // Marshal the event handler structure to unmanaged memory
                    // IMPORTANT: This memory must remain valid for the lifetime of the API
                    // We keep it allocated until nf_free() is called
                    // CRITICAL: If already initialized, free the old memory first to prevent leaks
                    if (_eventHandlerPtr != IntPtr.Zero)
                    {
                        // This shouldn't happen if _isInitialized check works, but be defensive
                        Marshal.FreeHGlobal(_eventHandlerPtr);
                        _eventHandlerPtr = IntPtr.Zero;
                    }

                    var eventHandlerSize = Marshal.SizeOf(typeof(NativeNetFilterApi.NF_EventHandler));
                    _eventHandlerPtr = Marshal.AllocHGlobal(eventHandlerSize);
                    // Use true to match samples - this will free any existing structure at this pointer
                    // (though in our case it's a new allocation, so this is just for consistency)
                    Marshal.StructureToPtr(eventHandler, _eventHandlerPtr, true);

                    // Initialize with the event handler structure (even though all callbacks are null)
                    // CRITICAL: nf_init might need to be called from the main/UI thread
                    // The samples call it directly from Main(), not from a background task
                    // For testing: Try marshalling to UI thread if available

                    // Try to marshal to UI thread if we're not on it
                    if (Application.MessageLoop && Application.OpenForms.Count > 0)
                    {
                        // We're in a Windows Forms app - marshal to UI thread
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
                            // Form is null, call directly
                            status = nf_init(_driverName, _eventHandlerPtr);
                        }
                    }
                    else
                    {
                        // No message loop or no forms, call directly (might crash)
                        status = nf_init(_driverName, _eventHandlerPtr);
                    }

                    // Set IP event handler if ICMP filtering is enabled (from Redirector.bin line 15762)
                    if (status == NF_STATUS.NF_STATUS_SUCCESS && _filterICMP && ipEventHandlerPtr != IntPtr.Zero)
                    {
                        try
                        {
                            NativeNetFilterApi.nf_setIPEventHandler(ipEventHandlerPtr);
                            _ipEventHandlerPtr = ipEventHandlerPtr; // Store for cleanup
                            Log.Information("ICMP/IP event handler registered (delay: {Delay}ms)", _icmpDelay);
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "Failed to set IP event handler - ICMP filtering may not work");
                            // Continue anyway - ICMP filtering is optional
                        }
                    }
                    else if (ipEventHandlerPtr != IntPtr.Zero)
                    {
                        // Free IP event handler if initialization failed
                        Marshal.FreeHGlobal(ipEventHandlerPtr);
                        ipEventHandlerPtr = IntPtr.Zero;
                    }

                    if (status != NF_STATUS.NF_STATUS_SUCCESS)
                    {
                        // Free the event handler memory if initialization failed
                        // since we won't be keeping it for the API lifetime
                        if (_eventHandlerPtr != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(_eventHandlerPtr);
                            _eventHandlerPtr = IntPtr.Zero;
                        }

                        // Get more details about the failure
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
                            // Ignore unregister errors during cleanup
                        }
                        throw new Exception(errorMsg);
                    }

                    // Initialize local proxy servers (SocksRedirector pattern)
                    if (!string.IsNullOrEmpty(_targetHost) && _targetPort > 0)
                    {
                        try
                        {
                            var socks5Target = new IPEndPoint(IPAddress.Parse(_targetHost), _targetPort);

                            // Initialize TCP proxy
                            _tcpProxy = new LocalTcpProxy();
                            if (!_tcpProxy.Initialize(_localProxyPort, socks5Target, _targetUser, _targetPass))
                            {
                                throw new Exception("Failed to initialize local TCP proxy");
                            }
                            _localProxyPort = _tcpProxy.ListenPort; // Use actual port assigned

                            // Initialize UDP proxy
                            _udpProxy = new LocalUdpProxy(socks5Target, _targetUser, _targetPass);

                            Log.Information("Local proxy servers initialized: TCP on port {TcpPort}, SOCKS5 target: {Socks5Target}",
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

                    // Create and apply filtering rules
                    try
                    {
                        ApplyRules();
                    }
                    catch (Exception ex)
                    {
                        // If rules fail, we should still free the event handler memory
                        // since initialization succeeded but rules failed
                        if (_eventHandlerPtr != IntPtr.Zero)
                        {
                            try
                            {
                                nf_free();
                            }
                            catch
                            {
                                // Ignore errors during cleanup
                            }
                            Marshal.FreeHGlobal(_eventHandlerPtr);
                            _eventHandlerPtr = IntPtr.Zero;
                        }
                        // Cleanup proxies
                        _tcpProxy?.Dispose();
                        _udpProxy?.Dispose();
                        throw new Exception($"Failed to apply filtering rules: {ex.Message}", ex);
                    }

                    _isInitialized = true;
                    return true;
                }
                catch (Exception ex)
                {
                    // Re-throw with context for better error messages
                    throw new Exception($"NetFilter initialization failed: {ex.Message}", ex);
                }
            });
        }

        public static Task<bool> FreeAsync()
        {
            return Task.Run(() =>
            {
                try
                {
                    if (!_isInitialized)
                        return true;

                    // Free the API first - this releases any references to the event handler
                    nf_free();

                    // Now safe to free the event handler memory
                    // The native API should have released all references to it
                    if (_eventHandlerPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(_eventHandlerPtr);
                        _eventHandlerPtr = IntPtr.Zero;
                    }

                    // Free IP event handler if it was allocated
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
                            // Ignore unregister errors
                        }
                    }

                    // Dispose and clear proxies
                    _tcpProxy?.Dispose();
                    _udpProxy?.Dispose();
                    _tcpProxy = null;
                    _udpProxy = null;

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

        public static bool aio_register(string value)
        {
            _driverName = value;
            return true;
        }

        // Statistics getters (from Redirector.bin aio_getUP and aio_getDL)
        public static long GetUploadBytes()
        {
            lock (_statsLock)
            {
                return _uploadBytes;
            }
        }

        public static long GetDownloadBytes()
        {
            lock (_statsLock)
            {
                return _downloadBytes;
            }
        }

        public static void ResetStatistics()
        {
            lock (_statsLock)
            {
                _uploadBytes = 0;
                _downloadBytes = 0;
            }
        }

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
                    // Function may not be available in all SDK versions
                    // Driver will be unregistered when service stops
                }
                catch (DllNotFoundException)
                {
                    // DLL not found - skip unregister
                }

                _isInitialized = false;
            }
            return true;
        }

        // Event handler creation removed - using IntPtr.Zero for rule-based redirection
        // Event handlers can be added later for advanced SOCKS5 protocol handling

        private static void ApplyRules()
        {
            Log.Information("[Rules] Starting rule application: Target={TargetHost}:{TargetPort}, FilterLoopback={FilterLoopback}, FilterIntranet={FilterIntranet}",
                _targetHost, _targetPort, _filterLoopback, _filterIntranet);
            nf_deleteRules();

            if (string.IsNullOrEmpty(_targetHost) || _targetPort <= 0)
            {
                Log.Warning("[Rules] Target not set! Host: '{TargetHost}', Port: {TargetPort}", _targetHost, _targetPort);
                return;
            }

            try
            {
                var targetIp = IPAddress.Parse(_targetHost);
                var redirectAddr = NativeNetFilterApi.CreateSockAddr(targetIp, _targetPort);
                var ipFamily = targetIp.AddressFamily == AddressFamily.InterNetworkV6 ? AF_INET6 : AF_INET;

                Log.Information("[Rules] Creating redirect rule: Target={TargetIp}:{TargetPort}, IPFamily={IpFamily}, HandlePatterns={HandleCount}, BypassPatterns={BypassCount}",
                    targetIp, _targetPort, ipFamily, _handlePatterns.Count, _bypassPatterns.Count);

                // Add FilterLoopback bypass rules (if FilterLoopback is false)
                // From Redirector.bin lines 15581-15603: bypass 127.0.0.1/8
                if (!_filterLoopback)
                {
                    Log.Information("[Rules] Adding FilterLoopback bypass rules for 127.0.0.1/8");
                    var loopbackRuleV4 = CreateBypassRuleForNetwork(IPAddress.Parse("127.0.0.1"), IPAddress.Parse("255.0.0.0"), AF_INET, IPPROTO_TCP);
                    var loopbackRuleV4Copy = loopbackRuleV4;
                    nf_addRuleEx(ref loopbackRuleV4Copy, 1);

                    var loopbackRuleV6 = CreateBypassRuleForNetwork(IPAddress.IPv6Loopback, IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AF_INET6, IPPROTO_TCP);
                    var loopbackRuleV6Copy = loopbackRuleV6;
                    nf_addRuleEx(ref loopbackRuleV6Copy, 1);

                    // UDP loopback bypass
                    var loopbackUdpRuleV4 = CreateBypassRuleForNetwork(IPAddress.Parse("127.0.0.1"), IPAddress.Parse("255.0.0.0"), AF_INET, IPPROTO_UDP);
                    var loopbackUdpRuleV4Copy = loopbackUdpRuleV4;
                    nf_addRuleEx(ref loopbackUdpRuleV4Copy, 1);

                    var loopbackUdpRuleV6 = CreateBypassRuleForNetwork(IPAddress.IPv6Loopback, IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), AF_INET6, IPPROTO_UDP);
                    var loopbackUdpRuleV6Copy = loopbackUdpRuleV6;
                    nf_addRuleEx(ref loopbackUdpRuleV6Copy, 1);
                }

                // Add FilterIntranet bypass rules (if FilterIntranet is false)
                // From Redirector.bin lines 15605-15759: bypass private network ranges
                if (!_filterIntranet)
                {
                    Log.Information("[Rules] Adding FilterIntranet bypass rules for private network ranges");
                    var intranetRanges = new[]
                    {
                        (IPAddress.Parse("10.0.0.0"), IPAddress.Parse("255.0.0.0")),
                        (IPAddress.Parse("100.64.0.0"), IPAddress.Parse("255.192.0.0")),
                        (IPAddress.Parse("169.254.0.0"), IPAddress.Parse("255.255.0.0")),
                        (IPAddress.Parse("100.64.0.0"), IPAddress.Parse("255.240.0.0")), // Overlap with above, but matches C code
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

                // Add ICMP filtering rule (if FilterICMP is enabled)
                // From Redirector.bin lines 15761-15779: ICMP filtering with NF_FILTER_AS_IP_PACKETS flag
                if (_filterICMP)
                {
                    Log.Information("[Rules] Adding ICMP filtering rule (delay: {Delay}ms)", _icmpDelay);
                    var icmpRuleV4 = CreateIcmpRule(AF_INET);
                    var icmpRuleV4Copy = icmpRuleV4;
                    nf_addRuleEx(ref icmpRuleV4Copy, 0);

                    var icmpRuleV6 = CreateIcmpRule(AF_INET6);
                    var icmpRuleV6Copy = icmpRuleV6;
                    nf_addRuleEx(ref icmpRuleV6Copy, 0);
                }

                // Add bypass rules first (both IPv4 and IPv6, TCP and UDP) - these have highest priority
                foreach (var pattern in _bypassPatterns)
                {
                    // TCP bypass rules
                    var bypassRuleV4 = CreateBypassRule(pattern, AF_INET, IPPROTO_TCP);
                    var bypassCopyV4 = bypassRuleV4;
                    nf_addRuleEx(ref bypassCopyV4, 1); // Add to head (higher priority)

                    var bypassRuleV6 = CreateBypassRule(pattern, AF_INET6, IPPROTO_TCP);
                    var bypassCopyV6 = bypassRuleV6;
                    nf_addRuleEx(ref bypassCopyV6, 1);

                    // UDP bypass rules
                    var bypassUdpRuleV4 = CreateBypassRule(pattern, AF_INET, IPPROTO_UDP);
                    var bypassUdpCopyV4 = bypassUdpRuleV4;
                    nf_addRuleEx(ref bypassUdpCopyV4, 1);

                    var bypassUdpRuleV6 = CreateBypassRule(pattern, AF_INET6, IPPROTO_UDP);
                    var bypassUdpCopyV6 = bypassUdpRuleV6;
                    nf_addRuleEx(ref bypassUdpCopyV6, 1);
                }

                // Only create redirect rules if we have handle patterns (process filtering)
                // If no handle patterns, don't redirect anything (process filtering mode)
                if (_handlePatterns.Count > 0)
                {
                    Log.Information("[Rules] Creating {Count} handle rules for process filtering (TCP and UDP)", _handlePatterns.Count);
                    // Add handle rules for specific processes only (TCP and UDP)
                    foreach (var pattern in _handlePatterns)
                    {
                        // TCP handle rules
                        var handleRuleV4 = CreateHandleRule(pattern, redirectAddr, AF_INET, IPPROTO_TCP);
                        var handleCopyV4 = handleRuleV4;
                        nf_addRuleEx(ref handleCopyV4, 1); // Add to head

                        var handleRuleV6 = CreateHandleRule(pattern, redirectAddr, AF_INET6, IPPROTO_TCP);
                        var handleCopyV6 = handleRuleV6;
                        nf_addRuleEx(ref handleCopyV6, 1);

                        // UDP handle rules
                        var handleUdpRuleV4 = CreateHandleRule(pattern, redirectAddr, AF_INET, IPPROTO_UDP);
                        var handleUdpCopyV4 = handleUdpRuleV4;
                        nf_addRuleEx(ref handleUdpCopyV4, 1);

                        var handleUdpRuleV6 = CreateHandleRule(pattern, redirectAddr, AF_INET6, IPPROTO_UDP);
                        var handleUdpCopyV6 = handleUdpRuleV6;
                        nf_addRuleEx(ref handleUdpCopyV6, 1);

                        Log.Information("[Rules] Added handle rule for process: {ProcessPattern} (TCP and UDP)", pattern);
                    }
                }
                else
                {
                    Log.Information("[Rules] No handle patterns defined - creating main redirect rule for all processes");
                    // No handle patterns - create main redirect rule for all processes (backward compatibility)
                    // TCP rules
                    var mainRuleV4 = CreateRedirectRule(redirectAddr, AF_INET, IPPROTO_TCP);
                    var ruleCopyV4 = mainRuleV4;
                    var resultV4 = nf_addRuleEx(ref ruleCopyV4, 0);
                    Log.Information("[Rules] IPv4 TCP redirect rule added: Result={Result}", resultV4);

                    if (ipFamily == AF_INET6 || targetIp.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        var mainRuleV6 = CreateRedirectRule(redirectAddr, AF_INET6, IPPROTO_TCP);
                        var ruleCopyV6 = mainRuleV6;
                        nf_addRuleEx(ref ruleCopyV6, 0);
                    }

                    // UDP rules
                    var mainUdpRuleV4 = CreateRedirectRule(redirectAddr, AF_INET, IPPROTO_UDP);
                    var udpRuleCopyV4 = mainUdpRuleV4;
                    nf_addRuleEx(ref udpRuleCopyV4, 0);
                    Log.Information("[Rules] IPv4 UDP redirect rule added");

                    if (ipFamily == AF_INET6 || targetIp.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        var mainUdpRuleV6 = CreateRedirectRule(redirectAddr, AF_INET6, IPPROTO_UDP);
                        var udpRuleCopyV6 = mainUdpRuleV6;
                        nf_addRuleEx(ref udpRuleCopyV6, 0);
                    }
                }
            }
            catch (Exception ex)
            {
                // If hostname resolution fails, rules won't be applied
                Log.Error(ex, "[Rules] ERROR: Failed to apply rules: {Message}", ex.Message);
            }
        }

        private static NF_RULE_EX CreateRedirectRule(byte[] redirectAddr, int ipFamily, int protocol = IPPROTO_TCP)
        {
            uint filteringFlag;
            if (protocol == IPPROTO_TCP)
            {
                // TCP: Use NF_INDICATE_CONNECT_REQUESTS to modify remoteAddress in tcpConnectRequest callback
                // NF_CONTROL_FLOW is required to actually control the connection and data flow
                // NF_DISABLE_REDIRECT_PROTECTION prevents blocking of redirected connections from local proxy
                // Note: We're NOT using NF_REDIRECT here - we'll modify remoteAddress in tcpConnectRequest instead
                filteringFlag = (uint)(NF_FILTERING_FLAG.NF_FILTER | NF_FILTERING_FLAG.NF_INDICATE_CONNECT_REQUESTS | NF_FILTERING_FLAG.NF_CONTROL_FLOW | NF_FILTERING_FLAG.NF_DISABLE_REDIRECT_PROTECTION);
            }
            else
            {
                // UDP: Connectionless protocol
                // Use NF_REDIRECT, NF_INDICATE_CONNECT_REQUESTS, and NF_CONTROL_FLOW for UDP
                // NF_REDIRECT allows inline redirection at the driver layer (sets redirectTo in rule)
                // NF_INDICATE_CONNECT_REQUESTS is needed to get udpConnectRequest callback to store state
                // NF_CONTROL_FLOW is still needed to intercept sends/receives for packet wrapping
                // NF_DISABLE_REDIRECT_PROTECTION prevents blocking of redirected connections from local proxy
                filteringFlag = (uint)(NF_FILTERING_FLAG.NF_FILTER | NF_FILTERING_FLAG.NF_REDIRECT | NF_FILTERING_FLAG.NF_INDICATE_CONNECT_REQUESTS | NF_FILTERING_FLAG.NF_CONTROL_FLOW | NF_FILTERING_FLAG.NF_DISABLE_REDIRECT_PROTECTION);
            }

            var rule = new NF_RULE_EX
            {
                protocol = (byte)protocol,
                processId = 0,
                // For UDP, use NF_D_BOTH to intercept both outgoing and incoming packets
                // (responses from relay endpoint are incoming)
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
                localProxyProcessId = _localProxyProcessId // Critical: Set to prevent redirect protection from blocking local proxy
            };

            // For UDP, we don't use NF_REDIRECT - we'll send packets directly to the UDP relay endpoint
            // (obtained via UDP ASSOCIATE) in UdpSend

            return rule;
        }

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

        // Create bypass rule for a network range (for FilterLoopback and FilterIntranet)
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

            // Set remote IP address and mask
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

        private static NF_RULE_EX CreateHandleRule(string processNamePattern, byte[] redirectAddr, int ipFamily, int protocol = IPPROTO_TCP)
        {
            var rule = CreateRedirectRule(redirectAddr, ipFamily, protocol);
            rule.processName = processNamePattern;
            return rule;
        }

        // Create ICMP filtering rule (from Redirector.bin lines 15761-15779)
        // Uses NF_FILTER_AS_IP_PACKETS flag to indicate packets via ipSend/ipReceive
        private static NF_RULE_EX CreateIcmpRule(int ipFamily)
        {
            return new NF_RULE_EX
            {
                protocol = IPPROTO_ICMP,
                processId = 0,
                direction = (byte)NF_DIRECTION.NF_D_BOTH, // ICMP is bidirectional
                localPort = 0,
                remotePort = 0,
                ip_family = (ushort)ipFamily,
                localIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                localIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddress = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                remoteIpAddressMask = new byte[NF_MAX_IP_ADDRESS_LENGTH],
                // NF_FILTER_AS_IP_PACKETS = 128: Indicate the traffic as IP packets via ipSend/ipReceive
                // NF_READONLY = 256: Don't block the IP packets and indicate them to ipSend/ipReceive only for monitoring
                filteringFlag = (uint)(NF_FILTERING_FLAG.NF_FILTER | NF_FILTERING_FLAG.NF_FILTER_AS_IP_PACKETS | NF_FILTERING_FLAG.NF_READONLY),
                processName = string.Empty,
                localPortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                remotePortRange = new NF_PORT_RANGE { valueLow = 0, valueHigh = 0 },
                redirectTo = new byte[NF_MAX_ADDRESS_LENGTH],
                localProxyProcessId = 0
            };
        }

        /// <summary>
        /// Maps NFConfig properties to Redirector.Dial calls for comprehensive configuration.
        /// This method provides a complete integration between NFConfig and Redirector.
        /// </summary>
        public static void ConfigureFromNFConfig(Configuration.NFConfig config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            Log.Information("[Config] Applying NFConfig to Redirector...");

            // Basic filtering flags
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

            // DNS configuration
            if (config.HandleOnlyDNS.HasValue)
                Dial(NameList.AIO_DNSONLY, config.HandleOnlyDNS.Value);

            if (config.DNSProxy.HasValue)
                Dial(NameList.AIO_DNSPROX, config.DNSProxy.Value);

            if (!string.IsNullOrEmpty(config.DNSHost))
            {
                try
                {
                    // Parse DNSHost (format: "host:port" or just "host")
                    var dnsParts = config.DNSHost.Split(':');
                    var dnsHost = dnsParts[0];
                    var dnsPort = dnsParts.Length > 1 && ushort.TryParse(dnsParts[1], out var port) ? port : (ushort)53;

                    Dial(NameList.AIO_DNSHOST, dnsHost);
                    Dial(NameList.AIO_DNSPORT, dnsPort.ToString());
                    Log.Information("[Config] DNS server configured: {DnsHost}:{DnsPort}", dnsHost, dnsPort);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "[Config] Failed to parse DNSHost: {DnsHost}", config.DNSHost);
                }
            }

            // ICMP delay
            if (config.ICMPDelay.HasValue)
            {
                Dial(NameList.AIO_ICMPING, config.ICMPDelay.Value.ToString());
                Log.Information("[Config] ICMP delay configured: {Delay}ms", config.ICMPDelay.Value);
            }

            // Local proxy port (must be set before InitAsync())
            if (config.LocalProxyPort.HasValue)
            {
                Dial(NameList.AIO_LOCALPROXYPORT, config.LocalProxyPort.Value.ToString());
                Log.Information("[Config] Local proxy port configured: {Port}", config.LocalProxyPort.Value);
            }

            // Process filtering rules
            Dial(NameList.AIO_CLRNAME, ""); // Clear existing rules

            if (config.Bypass != null && config.Bypass.Count > 0)
            {
                Log.Information("[Config] Adding {Count} bypass patterns", config.Bypass.Count);
                foreach (var pattern in config.Bypass)
                {
                    if (!string.IsNullOrEmpty(pattern))
                    {
                        Dial(NameList.AIO_BYPNAME, pattern);
                        Log.Debug("[Config] Added bypass pattern: {Pattern}", pattern);
                    }
                }
            }

            if (config.Handle != null && config.Handle.Count > 0)
            {
                Log.Information("[Config] Adding {Count} handle patterns", config.Handle.Count);
                foreach (var pattern in config.Handle)
                {
                    if (!string.IsNullOrEmpty(pattern))
                    {
                        Dial(NameList.AIO_ADDNAME, pattern);
                        Log.Debug("[Config] Added handle pattern: {Pattern}", pattern);
                    }
                }
            }

            Log.Information("[Config] NFConfig applied successfully");
        }
    }
}
