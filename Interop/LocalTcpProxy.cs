using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using OmniPoss.Infrastructure.Interop;
using Serilog;

namespace OmniPoss.Interop
{
    /// <summary>
    /// Local TCP proxy server that handles SOCKS5 protocol conversion.
    /// Listens on localhost (port 8888 by default) and proxies redirected connections to the target SOCKS5 server.
    /// Implements the SocksRedirector pattern: kernel driver redirects intercepted connections here,
    /// this proxy retrieves original destination and establishes SOCKS5 connection to core.
    /// </summary>
    internal class LocalTcpProxy : IDisposable
    {
        private TcpListener? _ipv4Listener;
        private TcpListener? _ipv6Listener;
        private ushort _listenPort;
        private bool _isInitialized = false;
        private readonly CancellationTokenSource _cancellationTokenSource = new();
        private readonly ConcurrentDictionary<ulong, TcpProxyConnection> _connections = new();
        private ulong _nextConnectionId = 1;

        /// <summary>
        /// Connection info mapping keyed by local port. Used to map redirected connections back to original destination.
        /// </summary>
        private readonly ConcurrentDictionary<ushort, NativeNetFilterApi.NF_TCP_CONN_INFO> _connInfoMap = new();

        private IPEndPoint? _socks5Target;
        private string? _socks5Username;
        private string? _socks5Password;

        public ushort ListenPort => _listenPort;
        public bool IsIPv4Available { get; private set; }
        public bool IsIPv6Available { get; private set; }
        public bool IsInitialized => _isInitialized;

        /// <summary>
        /// Store connection info keyed by local port. Used to retrieve original destination when proxy accepts connection.
        /// </summary>
        public void SetConnInfo(NativeNetFilterApi.NF_TCP_CONN_INFO connInfo)
        {
            ushort localPort = ExtractPort(connInfo.localAddress, connInfo.ip_family);
            if (localPort > 0)
            {
                _connInfoMap[localPort] = connInfo;
            }
        }

        /// <summary>
        /// Get connection info by remote port (which is actually the local port of the original connection).
        /// </summary>
        public bool GetRemoteAddress(IPEndPoint remoteEndPoint, out NativeNetFilterApi.NF_TCP_CONN_INFO connInfo)
        {
            ushort port = (ushort)remoteEndPoint.Port;
            if (_connInfoMap.TryRemove(port, out connInfo))
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Extracts port number from sockaddr structure (IPv4 or IPv6).
        /// </summary>
        /// <param name="sockAddr">sockaddr structure bytes.</param>
        /// <param name="ipFamily">Address family (2=AF_INET, 23=AF_INET6).</param>
        /// <returns>Port number in host byte order, or 0 if extraction fails.</returns>
        private ushort ExtractPort(byte[] sockAddr, ushort ipFamily)
        {
            if (sockAddr == null || sockAddr.Length < 4)
                return 0;

            if (ipFamily == 2) // AF_INET
            {
                return (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(sockAddr, 2));
            }
            else if (ipFamily == 23) // AF_INET6
            {
                return (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(sockAddr, 2));
            }
            return 0;
        }

        /// <summary>
        /// Initialize the local TCP proxy server.
        /// </summary>
        /// <summary>
        /// Initializes the local TCP proxy server. Sets up IPv4 and IPv6 listeners with socket reuse option for rapid reloads.
        /// </summary>
        /// <param name="port">Port to listen on (typically 8888).</param>
        /// <param name="socks5Target">Target SOCKS5 server endpoint.</param>
        /// <param name="username">Optional SOCKS5 username.</param>
        /// <param name="password">Optional SOCKS5 password.</param>
        /// <returns>True if at least one listener started successfully.</returns>
        public bool Initialize(ushort port, IPEndPoint socks5Target, string? username = null, string? password = null)
        {
            if (_isInitialized)
            {
                Dispose();
            }

            _listenPort = port;
            _socks5Target = socks5Target;
            _socks5Username = username;
            _socks5Password = password;

            try
            {
                try
                {
                    _ipv4Listener = new TcpListener(IPAddress.Loopback, port);
                    // Socket reuse allows binding even if port is in TIME_WAIT state (critical for reloads)
                    _ipv4Listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    _ipv4Listener.Start();
                    _ = AcceptConnectionsAsync(_ipv4Listener, AddressFamily.InterNetwork, _cancellationTokenSource.Token);
                    IsIPv4Available = true;
                    Log.Information("LocalTcpProxy: IPv4 listener started on {Address}:{Port}", IPAddress.Loopback, port);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "LocalTcpProxy: Failed to start IPv4 listener");
                }

                try
                {
                    _ipv6Listener = new TcpListener(IPAddress.IPv6Loopback, port);
                    // Socket reuse allows binding even if port is in TIME_WAIT state (critical for reloads)
                    _ipv6Listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    _ipv6Listener.Start();
                    _ = AcceptConnectionsAsync(_ipv6Listener, AddressFamily.InterNetworkV6, _cancellationTokenSource.Token);
                    IsIPv6Available = true;
                    Log.Information("LocalTcpProxy: IPv6 listener started on {Address}:{Port}", IPAddress.IPv6Loopback, port);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "LocalTcpProxy: Failed to start IPv6 listener");
                }

                if (!IsIPv4Available && !IsIPv6Available)
                {
                    Log.Error("LocalTcpProxy: Failed to start any listener");
                    return false;
                }

                _isInitialized = true;
                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "LocalTcpProxy: Initialization failed");
                Dispose();
                return false;
            }
        }

        /// <summary>
        /// Accepts incoming TCP connections from the kernel redirector and creates proxy connections.
        /// </summary>
        /// <param name="listener">TCP listener to accept connections from.</param>
        /// <param name="ipFamily">Address family (IPv4 or IPv6).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task AcceptConnectionsAsync(TcpListener listener, AddressFamily ipFamily, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var client = await listener.AcceptTcpClientAsync();
                    if (client == null)
                        continue;

                    // Remote endpoint is actually the local endpoint of the original connection (kernel redirects to us)
                    var remoteEndPoint = (IPEndPoint?)client.Client.RemoteEndPoint;
                    if (remoteEndPoint == null)
                    {
                        client.Close();
                        continue;
                    }

                    var connectionId = Interlocked.Increment(ref _nextConnectionId);
                    var connection = new TcpProxyConnection(connectionId, client, ipFamily, remoteEndPoint, _socks5Target!, _socks5Username, _socks5Password, this);
                    _connections[connectionId] = connection;

                    _ = HandleConnectionAsync(connection, cancellationToken);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!cancellationToken.IsCancellationRequested)
                    {
                        Log.Error(ex, "LocalTcpProxy: Error accepting connection");
                    }
                }
            }
        }

        /// <summary>
        /// Handles a single TCP proxy connection asynchronously.
        /// </summary>
        /// <param name="connection">TCP proxy connection to handle.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task HandleConnectionAsync(TcpProxyConnection connection, CancellationToken cancellationToken)
        {
            try
            {
                await connection.ProcessAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "LocalTcpProxy: Error handling connection {ConnectionId}", connection.Id);
            }
            finally
            {
                _connections.TryRemove(connection.Id, out _);
                connection.Dispose();
            }
        }

        public bool IsIPFamilyAvailable(AddressFamily ipFamily)
        {
            return ipFamily switch
            {
                AddressFamily.InterNetwork => IsIPv4Available,
                AddressFamily.InterNetworkV6 => IsIPv6Available,
                _ => false
            };
        }

        public void Dispose()
        {
            if (!_isInitialized)
                return;

            _cancellationTokenSource.Cancel();

            try
            {
                _ipv4Listener?.Stop();
                _ipv4Listener?.Server?.Dispose();
            }
            catch { }
            finally
            {
                _ipv4Listener = null;
            }

            try
            {
                _ipv6Listener?.Stop();
                _ipv6Listener?.Server?.Dispose();
            }
            catch { }
            finally
            {
                _ipv6Listener = null;
            }

            foreach (var connection in _connections.Values)
            {
                connection.Dispose();
            }
            _connections.Clear();
            _connInfoMap.Clear();

            _cancellationTokenSource.Dispose();
            _isInitialized = false;

            Log.Information("LocalTcpProxy: Disposed");
        }
    }

    /// <summary>
    /// Represents a single TCP proxy connection handling SOCKS5 protocol conversion.
    /// Retrieves original destination from connection info map, performs SOCKS5 handshake (auth + CONNECT),
    /// then relays data bidirectionally between client and SOCKS5 server.
    /// </summary>
    /// <remarks>
    /// Initializes a new TCP proxy connection instance.
    /// </remarks>
    /// <param name="id">Connection ID.</param>
    /// <param name="client">TCP client from kernel redirector.</param>
    /// <param name="ipFamily">Address family (IPv4 or IPv6).</param>
    /// <param name="remoteEndPoint">Remote endpoint (actually local endpoint of original connection).</param>
    /// <param name="socks5Target">Target SOCKS5 server endpoint.</param>
    /// <param name="username">Optional SOCKS5 username.</param>
    /// <param name="password">Optional SOCKS5 password.</param>
    /// <param name="proxy">Parent LocalTcpProxy instance.</param>
    internal class TcpProxyConnection(ulong id, TcpClient client, AddressFamily ipFamily, IPEndPoint remoteEndPoint, IPEndPoint socks5Target, string? username, string? password, LocalTcpProxy proxy) : IDisposable
    {
        private readonly ulong _id = id;
        private readonly TcpClient _client = client;
        private readonly AddressFamily _ipFamily = ipFamily;
        private readonly IPEndPoint _remoteEndPoint = remoteEndPoint; // Original connection's local endpoint
        private readonly IPEndPoint _socks5Target = socks5Target;
        private readonly string? _username = username;
        private readonly string? _password = password;
        private readonly LocalTcpProxy _proxy = proxy;
        private TcpClient? _socks5Client;
        private NetworkStream? _clientStream = client.GetStream();
        private NetworkStream? _socks5Stream;
        private bool _isDisposed = false;

        private enum Socks5State
        {
            Auth,
            AuthNegotiation,
            Connect,
            Connected,
            Error
        }

#pragma warning disable CS0414 // Field is assigned but never used (kept for potential future debugging)
        private Socks5State _state = Socks5State.Auth;
#pragma warning restore CS0414

        public ulong Id => _id;

        /// <summary>
        /// Processes the TCP proxy connection: retrieves original destination, performs SOCKS5 handshake, and relays data.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task ProcessAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Get original destination from connection info map (stored before kernel redirect)
                if (!_proxy.GetRemoteAddress(_remoteEndPoint, out var connInfo))
                {
                    Log.Warning("TcpProxyConnection {Id}: Could not find connection info for port {Port}", _id, _remoteEndPoint.Port);
                    return;
                }

                // Extract original destination from connInfo
                var originalDestination = ExtractOriginalDestination(connInfo);
                if (originalDestination == null)
                {
                    Log.Warning("TcpProxyConnection {Id}: Could not extract original destination", _id);
                    return;
                }


                // Connect to SOCKS5 server
                _socks5Client = new TcpClient();
                await _socks5Client.ConnectAsync(_socks5Target.Address, _socks5Target.Port);
                _socks5Stream = _socks5Client.GetStream();

                // Send SOCKS5 auth request
                _state = Socks5State.Auth;
                await SendAuthRequestAsync();

                // Wait for auth response
                var authResponse = new byte[2];
                var bytesRead = await _socks5Stream.ReadAsync(authResponse, cancellationToken);
                if (bytesRead < 2 || authResponse[0] != 0x05)
                {
                    Log.Warning("TcpProxyConnection {Id}: Invalid auth response", _id);
                    return;
                }

                var method = authResponse[1];

                // Handle username/password auth if required
                if (method == 0x02 && !string.IsNullOrEmpty(_username))
                {
                    _state = Socks5State.AuthNegotiation;
                    await SendUsernamePasswordAuthAsync();

                    bytesRead = await _socks5Stream.ReadAsync(authResponse, cancellationToken);
                    if (bytesRead < 2 || authResponse[0] != 0x01 || authResponse[1] != 0x00)
                    {
                        Log.Warning("TcpProxyConnection {Id}: Username/password auth failed", _id);
                        return;
                    }
                }
                else if (method != 0x00)
                {
                    Log.Warning("TcpProxyConnection {Id}: Unsupported auth method {Method}", _id, method);
                    return;
                }

                // Send SOCKS5 CONNECT request with original destination
                _state = Socks5State.Connect;
                await SendConnectRequestAsync(originalDestination);

                // Wait for CONNECT response
                var connectResponse = await ReadConnectResponseAsync(cancellationToken);
                if (!connectResponse)
                {
                    Log.Warning("TcpProxyConnection {Id}: CONNECT request failed", _id);
                    return;
                }

                // Start bidirectional data relay
                _state = Socks5State.Connected;

                var clientToSocks5 = RelayDataAsync(_clientStream!, _socks5Stream, cancellationToken);
                var socks5ToClient = RelayDataAsync(_socks5Stream, _clientStream!, cancellationToken);

                await Task.WhenAny(clientToSocks5, socks5ToClient);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "TcpProxyConnection {Id}: Error in ProcessAsync", _id);
            }
        }

        /// <summary>
        /// Extracts original destination IP and port from NetFilter connection info structure.
        /// </summary>
        /// <param name="connInfo">NetFilter TCP connection information.</param>
        /// <returns>Original destination endpoint or null if extraction fails.</returns>
        private IPEndPoint? ExtractOriginalDestination(NativeNetFilterApi.NF_TCP_CONN_INFO connInfo)
        {
            try
            {
                // Check the address family from the sockaddr structure itself
                ushort addrFamily = BitConverter.ToUInt16(connInfo.remoteAddress, 0);

                if (addrFamily == 2) // AF_INET
                {
                    // sockaddr_in structure: family(2) + port(2) + addr(4) = 8 bytes
                    if (connInfo.remoteAddress.Length < 8)
                        return null;

                    ushort port = BitConverter.ToUInt16(connInfo.remoteAddress, 2);
                    port = (ushort)IPAddress.NetworkToHostOrder((short)port);

                    uint ipAddr = BitConverter.ToUInt32(connInfo.remoteAddress, 4);
                    var ip = new IPAddress(BitConverter.GetBytes(ipAddr));

                    return new IPEndPoint(ip, port);
                }
                else if (addrFamily == 23) // AF_INET6
                {
                    // sockaddr_in6 structure: family(2) + port(2) + flowinfo(4) + addr(16) = 24 bytes
                    if (connInfo.remoteAddress.Length < 24)
                        return null;

                    ushort port = BitConverter.ToUInt16(connInfo.remoteAddress, 2);
                    port = (ushort)IPAddress.NetworkToHostOrder((short)port);

                    byte[] ipBytes = new byte[16];
                    Array.Copy(connInfo.remoteAddress, 8, ipBytes, 0, 16);
                    var ip = new IPAddress(ipBytes);

                    return new IPEndPoint(ip, port);
                }
                else
                {
                    Log.Warning("TcpProxyConnection {Id}: Unknown address family in remoteAddress: {Family}", _id, addrFamily);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "TcpProxyConnection {Id}: Error extracting destination", _id);
            }
            return null;
        }

        /// <summary>
        /// Sends SOCKS5 CONNECT request to establish connection to original destination.
        /// </summary>
        /// <param name="destination">Original destination endpoint.</param>
        private async Task SendConnectRequestAsync(IPEndPoint destination)
        {
            byte[] request;
            if (destination.AddressFamily == AddressFamily.InterNetwork)
            {
                // IPv4 CONNECT request
                request = new byte[10];
                request[0] = 0x05; // Version
                request[1] = 0x01; // CONNECT
                request[2] = 0x00; // Reserved
                request[3] = 0x01; // IPv4 address type
                var ipBytes = destination.Address.GetAddressBytes();
                Array.Copy(ipBytes, 0, request, 4, 4);
                var portBytes = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)destination.Port));
                Array.Copy(portBytes, 0, request, 8, 2);
            }
            else
            {
                // IPv6 CONNECT request
                request = new byte[22];
                request[0] = 0x05; // Version
                request[1] = 0x01; // CONNECT
                request[2] = 0x00; // Reserved
                request[3] = 0x04; // IPv6 address type
                var ipBytes = destination.Address.GetAddressBytes();
                Array.Copy(ipBytes, 0, request, 4, 16);
                var portBytes = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)destination.Port));
                Array.Copy(portBytes, 0, request, 20, 2);
            }
            await _socks5Stream!.WriteAsync(request);
        }

        /// <summary>
        /// Reads SOCKS5 CONNECT response and validates success.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if CONNECT succeeded, false otherwise.</returns>
        private async Task<bool> ReadConnectResponseAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[4];
            var bytesRead = await _socks5Stream!.ReadAsync(buffer, cancellationToken);
            if (bytesRead < 4 || buffer[0] != 0x05 || buffer[1] != 0x00)
            {
                return false;
            }

            var addressType = buffer[3];
            int responseLength;
            if (addressType == 0x01) // IPv4
            {
                responseLength = 10;
            }
            else if (addressType == 0x04) // IPv6
            {
                responseLength = 22;
            }
            else
            {
                return false;
            }

            var fullResponse = new byte[responseLength];
            Array.Copy(buffer, 0, fullResponse, 0, 4);
            bytesRead = await _socks5Stream.ReadAsync(fullResponse.AsMemory(4, responseLength - 4), cancellationToken);
            return bytesRead == responseLength - 4;
        }

        /// <summary>
        /// Sends SOCKS5 authentication method selection request.
        /// </summary>
        private async Task SendAuthRequestAsync()
        {
            byte[] request;
            if (!string.IsNullOrEmpty(_username))
            {
                request = new byte[] { 0x05, 0x01, 0x02 }; // Version 5, 1 method, username/password
            }
            else
            {
                request = new byte[] { 0x05, 0x01, 0x00 }; // Version 5, 1 method, no auth
            }
            await _socks5Stream!.WriteAsync(request);
        }

        /// <summary>
        /// Sends SOCKS5 username/password authentication request.
        /// </summary>
        private async Task SendUsernamePasswordAuthAsync()
        {
            var usernameBytes = System.Text.Encoding.UTF8.GetBytes(_username!);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(_password ?? "");

            var request = new byte[3 + usernameBytes.Length + passwordBytes.Length];
            request[0] = 0x01; // Version
            request[1] = (byte)usernameBytes.Length;
            Array.Copy(usernameBytes, 0, request, 2, usernameBytes.Length);
            request[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
            Array.Copy(passwordBytes, 0, request, 3 + usernameBytes.Length, passwordBytes.Length);

            await _socks5Stream!.WriteAsync(request);
        }

        /// <summary>
        /// Relays data bidirectionally between client and SOCKS5 streams.
        /// Called after SOCKS5 handshake is complete (auth and CONNECT).
        /// </summary>
        /// <param name="source">Source stream to read from.</param>
        /// <param name="destination">Destination stream to write to.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        private async Task RelayDataAsync(NetworkStream source, NetworkStream destination, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = await source.ReadAsync(buffer, cancellationToken)) > 0)
                {
                    await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                }
            }
            catch
            {
            }
        }

        public void Dispose()
        {
            if (_isDisposed)
                return;

            _isDisposed = true;
            try { _clientStream?.Close(); } catch { }
            try { _socks5Stream?.Close(); } catch { }
            try { _client?.Close(); } catch { }
            try { _socks5Client?.Close(); } catch { }
        }
    }
}
