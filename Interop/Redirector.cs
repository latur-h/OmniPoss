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

        private static long _uploadBytes = 0;
        private static long _downloadBytes = 0;
        private static readonly object _statsLock = new();
        
        // Track per-connection manual byte counts to avoid double-counting with NF stats
        private static readonly ConcurrentDictionary<ulong, (long upload, long download)> _connectionManualStats = new();

        private static LocalTcpProxy? _tcpProxy;
        private static LocalUdpProxy? _udpProxy;
        private static ushort _localProxyPort = 8888;

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
            try
            {
                if (_filterParent && pConnInfo.processId == Environment.ProcessId)
                {
                    return;
                }

                var processName = GetProcessName(pConnInfo.processId);
                var processId = pConnInfo.processId;
                var processIdCopy = processId;

                try
                {
                    if (NativeNetFilterApi.nf_tcpIsProxy(pConnInfo.processId))
                    {
                        return;
                    }
                }
                catch (EntryPointNotFoundException) { }
                catch (DllNotFoundException) { }

                if (CheckBypassName(pConnInfo.processId))
                {
                    return;
                }

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

                if (originalIp != null && IsPrivateAddress(originalIp))
                {
                    return;
                }

                if (_tcpProxy != null && _tcpProxy.IsInitialized)
                {
                    var localProxyPort = _tcpProxy.ListenPort;
                    IPAddress localProxyIp = pConnInfo.ip_family == AF_INET6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
                    var localProxyAddr = NativeNetFilterApi.CreateSockAddr(localProxyIp, localProxyPort);
                    var originalRemoteAddr = (byte[])pConnInfo.remoteAddress.Clone();
                    
                    Array.Copy(localProxyAddr, pConnInfo.remoteAddress, Math.Min(localProxyAddr.Length, pConnInfo.remoteAddress.Length));
                    pConnInfo.ip_family = (ushort)(localProxyIp.AddressFamily == AddressFamily.InterNetworkV6 ? AF_INET6 : AF_INET);
                    pConnInfo.processId = (uint)Environment.ProcessId;

                    var connInfoCopy = pConnInfo;
                    connInfoCopy.remoteAddress = originalRemoteAddr;
                    connInfoCopy.localAddress = (byte[])pConnInfo.localAddress.Clone();
                    _tcpProxy.SetConnInfo(connInfoCopy);
                }
                else
                {
                    QueueLog(() => Log.Warning("[TCP] Local proxy not initialized! Connection {ConnectionId}", id));
                }
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[TCP] TcpConnectRequest ERROR for connection {ConnectionId}: {Message}", id, ex.Message));
            }
        }

        /// <summary>
        /// TCP connection established callback.
        /// </summary>
        private static void StubTcpConnected(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
        }

        /// <summary>
        /// TCP connection closed callback. Retrieves final statistics.
        /// </summary>
        private static void StubTcpClosed(ulong id, ref NativeNetFilterApi.NF_TCP_CONN_INFO pConnInfo)
        {
            try
            {
                bool usedNfStats = false;
                
                try
                {
                    var stat = new NativeNetFilterApi.NF_FLOWCTL_STAT();
                    var status = NativeNetFilterApi.nf_getTCPStat(id, ref stat);
                    if (status == NativeNetFilterApi.NF_STATUS.NF_STATUS_SUCCESS)
                    {
                        lock (_statsLock)
                        {
                            _downloadBytes += (long)stat.bytesIn;
                            _uploadBytes += (long)stat.bytesOut;
                        }
                        usedNfStats = true;
                    }
                }
                catch (EntryPointNotFoundException) { }
                catch (DllNotFoundException) { }

                if (!usedNfStats && _connectionManualStats.TryRemove(id, out var manualStats))
                {
                    lock (_statsLock)
                    {
                        _downloadBytes += manualStats.download;
                        _uploadBytes += manualStats.upload;
                    }
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
                _connectionManualStats.AddOrUpdate(id, (0, len), (key, existing) => (existing.upload, existing.download + len));
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
                _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
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

                if (CheckBypassName(pConnInfo.processId))
                {
                    return;
                }
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
        /// UDP connection closed callback. Retrieves final statistics and cleans up UDP proxy connection.
        /// </summary>
        private static void StubUdpClosed(ulong id, ref NativeNetFilterApi.NF_UDP_CONN_INFO pConnInfo)
        {
            try
            {
                bool usedNfStats = false;
                
                try
                {
                    var stat = new NativeNetFilterApi.NF_FLOWCTL_STAT();
                    var status = NativeNetFilterApi.nf_getUDPStat(id, ref stat);
                    if (status == NativeNetFilterApi.NF_STATUS.NF_STATUS_SUCCESS)
                    {
                        lock (_statsLock)
                        {
                            _downloadBytes += (long)stat.bytesIn;
                            _uploadBytes += (long)stat.bytesOut;
                        }
                        usedNfStats = true;
                    }
                }
                catch (EntryPointNotFoundException) { }
                catch (DllNotFoundException) { }

                if (!usedNfStats && _connectionManualStats.TryRemove(id, out var manualStats))
                {
                    lock (_statsLock)
                    {
                        _downloadBytes += manualStats.download;
                        _uploadBytes += manualStats.upload;
                    }
                }
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpClosed ERROR for connection {ConnectionId}", id));
            }
            finally
            {
                _udpProxy?.DeleteProxyConnection(id);
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
                _connectionManualStats.AddOrUpdate(id, (0, len), (key, existing) => (existing.upload, existing.download + len));
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpReceive ERROR for connection {ConnectionId}", id));
            }
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

                if (remotePort == 53 && _filterDNS)
                {
                    if (_dnsProxy && _udpProxy != null && remoteEndPoint != null)
                    {
                        byte[] data = new byte[len];
                        Marshal.Copy(buf, data, 0, len);
                        if (_udpProxy.UdpSend(id, data, len, remoteEndPoint, options, remoteAddress))
                        {
                            _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
                            return;
                        }
                    }
                    else
                    {
                        NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                        _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
                        return;
                    }
                }

                if (remoteEndPoint == null)
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
                    return;
                }

                bool isRedirectedToProxy = false;
                if (_tcpProxy != null && _tcpProxy.IsInitialized && _udpProxy != null)
                {
                    bool isLoopback = IPAddress.IsLoopback(remoteEndPoint.Address) || 
                                     remoteEndPoint.Address.Equals(IPAddress.Loopback) || 
                                     remoteEndPoint.Address.Equals(IPAddress.IPv6Loopback);
                    bool portMatches = remoteEndPoint.Port == _tcpProxy.ListenPort;
                    isRedirectedToProxy = isLoopback && portMatches;
                }

                if (!isRedirectedToProxy && IsPrivateAddress(remoteEndPoint.Address))
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
                    return;
                }

                if (_udpProxy != null)
                {
                    byte[] data = new byte[len];
                    Marshal.Copy(buf, data, 0, len);

                    if (_udpProxy.UdpSend(id, data, len, remoteEndPoint, options, remoteAddress))
                    {
                        _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
                        return;
                    }
                }

                NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
            }
            catch (Exception ex)
            {
                QueueLog(() => Log.Error(ex, "[UDP] UdpSend ERROR for connection {ConnectionId}", id));
                try
                {
                    NativeNetFilterApi.nf_udpPostSend(id, remoteAddress, buf, len, options);
                    _connectionManualStats.AddOrUpdate(id, (len, 0), (key, existing) => (existing.upload + len, existing.download));
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

                    lock (_statsLock)
                    {
                        _downloadBytes += len;
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

                    lock (_statsLock)
                    {
                        _uploadBytes += len;
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

        private struct ProcessInfo
        {
            public string Name;
            public string Path;
            public DateTime CachedAt;
        }

        private static readonly ConcurrentDictionary<uint, ProcessInfo> _processCache = new();
        private static readonly TimeSpan _processCacheTTL = TimeSpan.FromMinutes(5);
        private static readonly object _processCacheLock = new();
        private static GCHandle _processCacheHandle;

        private struct PatternMatchResult
        {
            public bool ShouldHandle;
            public bool ShouldBypass;
            public DateTime CachedAt;
        }

        private static readonly ConcurrentDictionary<uint, PatternMatchResult> _patternMatchCache = new();
        private static readonly TimeSpan _patternCacheTTL = TimeSpan.FromMinutes(5);
        private static GCHandle _patternCacheHandle;

        private static readonly ConcurrentQueue<Action> _logQueue = new();
        private static readonly CancellationTokenSource _logQueueCts = new();
        private static Task? _logProcessorTask = null;
        private static readonly object _logProcessorLock = new();

        /// <summary>
        /// Gets process name from process ID with caching to avoid slow lookups in callbacks.
        /// Uses NF kernel function which doesn't require admin privileges.
        /// </summary>
        private static string GetProcessName(uint processId)
        {
            if (processId == 0) return "Unknown";

            if (_processCache.TryGetValue(processId, out var cachedInfo))
            {
                if (DateTime.UtcNow - cachedInfo.CachedAt < _processCacheTTL)
                {
                    return cachedInfo.Name;
                }
                _processCache.TryRemove(processId, out _);
            }

            try
            {
                var nameBuf = new System.Text.StringBuilder(260);
                bool success = false;

                try
                {
                    success = NativeNetFilterApi.nf_getProcessNameFromKernel(processId, nameBuf, 260);
                }
                catch (EntryPointNotFoundException) { }
                catch (DllNotFoundException) { }

                if (!success)
                {
                    try
                    {
                        success = NativeNetFilterApi.nf_getProcessNameW(processId, nameBuf, 260);
                    }
                    catch (EntryPointNotFoundException) { }
                    catch (DllNotFoundException) { }
                }

                string processName;
                string? processPath = null;

                if (success && nameBuf.Length > 0)
                {
                    processPath = nameBuf.ToString();
                    processName = Path.GetFileNameWithoutExtension(processPath);
                }
                else
                {
                    // Final fallback to Process.GetProcessById (requires admin)
                    var process = Process.GetProcessById((int)processId);
                    processName = process.ProcessName;
                    try
                    {
                        processPath = process.MainModule?.FileName;
                    }
                    catch
                    {
                        processPath = processName;
                    }
                }

                var info = new ProcessInfo
                {
                    Name = processName,
                    Path = processPath ?? processName,
                    CachedAt = DateTime.UtcNow
                };
                _processCache[processId] = info;

                return processName;
            }
            catch (ArgumentException)
            {
                var failedInfo = new ProcessInfo
                {
                    Name = $"PID:{processId}",
                    Path = $"PID:{processId}",
                    CachedAt = DateTime.UtcNow
                };
                _processCache[processId] = failedInfo;
                return failedInfo.Name;
            }
            catch (Exception)
            {
                var failedInfo = new ProcessInfo
                {
                    Name = $"PID:{processId}",
                    Path = $"PID:{processId}",
                    CachedAt = DateTime.UtcNow
                };
                _processCache[processId] = failedInfo;
                return failedInfo.Name;
            }
        }

        /// <summary>
        /// Gets full process path from process ID with caching to avoid slow MainModule lookups.
        /// Uses NF kernel function which doesn't require admin privileges.
        /// </summary>
        private static string GetProcessPath(uint processId)
        {
            if (processId == 0) return "Unknown";

            if (_processCache.TryGetValue(processId, out var cachedInfo))
            {
                if (DateTime.UtcNow - cachedInfo.CachedAt < _processCacheTTL)
                {
                    return cachedInfo.Path;
                }
                _processCache.TryRemove(processId, out _);
            }

            try
            {
                var nameBuf = new System.Text.StringBuilder(260);
                bool success = false;

                try
                {
                    success = NativeNetFilterApi.nf_getProcessNameFromKernel(processId, nameBuf, 260);
                }
                catch (EntryPointNotFoundException) { }
                catch (DllNotFoundException) { }

                if (!success)
                {
                    try
                    {
                        success = NativeNetFilterApi.nf_getProcessNameW(processId, nameBuf, 260);
                    }
                    catch (EntryPointNotFoundException) { }
                    catch (DllNotFoundException) { }
                }

                string processName;
                string? processPath = null;

                if (success && nameBuf.Length > 0)
                {
                    processPath = nameBuf.ToString();
                    processName = Path.GetFileNameWithoutExtension(processPath);
                }
                else
                {
                    // Final fallback to Process.GetProcessById (requires admin)
                    var process = Process.GetProcessById((int)processId);
                    processName = process.ProcessName;
                    try
                    {
                        processPath = process.MainModule?.FileName;
                    }
                    catch
                    {
                        processPath = processName;
                    }
                }

                var info = new ProcessInfo
                {
                    Name = processName,
                    Path = processPath ?? processName,
                    CachedAt = DateTime.UtcNow
                };
                _processCache[processId] = info;

                return info.Path;
            }
            catch
            {
                var failedInfo = new ProcessInfo
                {
                    Name = $"PID:{processId}",
                    Path = $"PID:{processId}",
                    CachedAt = DateTime.UtcNow
                };
                _processCache[processId] = failedInfo;
                return failedInfo.Path;
            }
        }

        /// <summary>
        /// Checks if process matches handle patterns with caching to avoid repeated lookups.
        /// </summary>
        /// <param name="processId">Process ID to check.</param>
        /// <returns>True if process should be handled/redirected.</returns>
        private static bool CheckHandleName(uint processId)
        {
            if (_handlePatterns.Count == 0)
                return true;

            if (_patternMatchCache.TryGetValue(processId, out var cachedMatch))
            {
                if (DateTime.UtcNow - cachedMatch.CachedAt < _patternCacheTTL)
                {
                    return cachedMatch.ShouldHandle;
                }
                _patternMatchCache.TryRemove(processId, out _);
            }

            var processName = GetProcessName(processId);
            var processPath = GetProcessPath(processId);

            bool shouldHandle = false;
            foreach (var pattern in _handlePatterns)
            {
                if (string.IsNullOrEmpty(pattern))
                    continue;

                if (MatchesPattern(processName, pattern) || MatchesPattern(processPath, pattern))
                {
                    shouldHandle = true;
                    break;
                }
            }

            var matchResult = new PatternMatchResult
            {
                ShouldHandle = shouldHandle,
                ShouldBypass = false,
                CachedAt = DateTime.UtcNow
            };
            _patternMatchCache[processId] = matchResult;

            return shouldHandle;
        }

        /// <summary>
        /// Checks if process matches bypass patterns with caching to avoid repeated lookups.
        /// </summary>
        /// <param name="processId">Process ID to check.</param>
        /// <returns>True if process should be bypassed (not redirected).</returns>
        private static bool CheckBypassName(uint processId)
        {
            if (_bypassPatterns.Count == 0)
                return false;

            if (_patternMatchCache.TryGetValue(processId, out var cachedMatch))
            {
                if (DateTime.UtcNow - cachedMatch.CachedAt < _patternCacheTTL && cachedMatch.ShouldBypass)
                {
                    return cachedMatch.ShouldBypass;
                }
                _patternMatchCache.TryRemove(processId, out _);
            }

            var processName = GetProcessName(processId);
            var processPath = GetProcessPath(processId);

            bool shouldBypass = false;
            foreach (var pattern in _bypassPatterns)
            {
                if (string.IsNullOrEmpty(pattern))
                    continue;

                if (MatchesPattern(processName, pattern) || MatchesPattern(processPath, pattern))
                {
                    shouldBypass = true;
                    break;
                }
            }

            if (_patternMatchCache.TryGetValue(processId, out var existingMatch))
            {
                existingMatch.ShouldBypass = shouldBypass;
                existingMatch.CachedAt = DateTime.UtcNow;
                _patternMatchCache[processId] = existingMatch;
            }
            else
            {
                var matchResult = new PatternMatchResult
                {
                    ShouldHandle = false,
                    ShouldBypass = shouldBypass,
                    CachedAt = DateTime.UtcNow
                };
                _patternMatchCache[processId] = matchResult;
            }

            return shouldBypass;
        }

        /// <summary>
        /// Performs simple wildcard pattern matching (supports * and ?).
        /// Handles .exe extension normalization and case-insensitive comparison.
        /// </summary>
        private static bool MatchesPattern(string text, string pattern)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(pattern))
                return false;

            string normalizedText = text;
            string normalizedPattern = pattern;

            if (normalizedPattern.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && 
                !normalizedText.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                normalizedPattern = normalizedPattern.Substring(0, normalizedPattern.Length - 4);
            }
            else if (normalizedText.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && 
                     !normalizedPattern.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                normalizedText = normalizedText.Substring(0, normalizedText.Length - 4);
            }

            normalizedText = normalizedText.ToLowerInvariant();
            normalizedPattern = normalizedPattern.ToLowerInvariant();

            if (!normalizedPattern.Contains('*') && !normalizedPattern.Contains('?'))
            {
                return normalizedText == normalizedPattern;
            }
            int textIndex = 0;
            int patternIndex = 0;
            int textStar = -1;
            int patternStar = -1;

            while (textIndex < normalizedText.Length)
            {
                if (patternIndex < normalizedPattern.Length && (normalizedPattern[patternIndex] == '?' || normalizedPattern[patternIndex] == normalizedText[textIndex]))
                {
                    textIndex++;
                    patternIndex++;
                }
                else if (patternIndex < normalizedPattern.Length && normalizedPattern[patternIndex] == '*')
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

            while (patternIndex < normalizedPattern.Length && normalizedPattern[patternIndex] == '*')
                patternIndex++;

            return patternIndex == normalizedPattern.Length;
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

                    if (!_processCacheHandle.IsAllocated)
                    {
                        _processCacheHandle = GCHandle.Alloc(_processCache, GCHandleType.Normal);
                    }
                    if (!_patternCacheHandle.IsAllocated)
                    {
                        _patternCacheHandle = GCHandle.Alloc(_patternMatchCache, GCHandleType.Normal);
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
                    _processCache.Clear();
                    _patternMatchCache.Clear();

                    foreach (var handle in _callbackHandles)
                    {
                        if (handle.IsAllocated)
                        {
                            handle.Free();
                        }
                    }
                    _callbackHandles.Clear();
                    _callbackDelegates.Clear();

                    if (_processCacheHandle.IsAllocated)
                    {
                        _processCacheHandle.Free();
                    }
                    if (_patternCacheHandle.IsAllocated)
                    {
                        _patternCacheHandle.Free();
                    }

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
        /// Gets the total number of bytes uploaded.
        /// </summary>
        /// <returns>Total upload bytes.</returns>
        public static long GetUploadBytes()
        {
            lock (_statsLock)
            {
                return _uploadBytes;
            }
        }

        /// <summary>
        /// Gets the total number of bytes downloaded.
        /// </summary>
        /// <returns>Total download bytes.</returns>
        public static long GetDownloadBytes()
        {
            lock (_statsLock)
            {
                return _downloadBytes;
            }
        }

        /// <summary>
        /// Resets upload and download statistics to zero.
        /// </summary>
        public static void ResetStatistics()
        {
            lock (_statsLock)
            {
                _uploadBytes = 0;
                _downloadBytes = 0;
            }
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
    }
}
