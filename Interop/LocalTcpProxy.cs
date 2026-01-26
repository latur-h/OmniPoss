using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
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
        private Socket? _ipv4ListenSocket;
        private Socket? _ipv6ListenSocket;
        private ushort _listenPort;
        private bool _isInitialized = false;
        private readonly CancellationTokenSource _cancellationTokenSource = new();
        private readonly ConcurrentDictionary<ulong, TcpProxyConnection> _connections = new();
        private ulong _nextConnectionId = 1;

        /// <summary>
        /// Connection info mapping keyed by local port. Used to map redirected connections back to original destination.
        /// </summary>
        private readonly ConcurrentDictionary<ushort, NativeNetFilterApi.NF_TCP_CONN_INFO> _connInfoMap = new();

        private readonly ConcurrentDictionary<ushort, ConnectionInfoMetadata> _connInfoMetadata = new();

        private IPEndPoint? _socks5Target;
        private string? _socks5Username;
        private string? _socks5Password;

        private class PreAuthenticatedConnection
        {
            public TcpClient Client { get; set; } = null!;
            public NetworkStream Stream { get; set; } = null!;
            public DateTime CreatedAt { get; set; }
            public bool IsAuthenticated { get; set; }
        }

        private readonly ConcurrentQueue<PreAuthenticatedConnection> _connectionPool = new();
        private const int MinPoolSize = 5;
        private const int PoolRefreshIntervalMs = 5000;
        private const int MaxConnectionAgeSeconds = 30;
        private Task? _poolMaintenanceTask;

        private readonly ConcurrentQueue<SocketAsyncEventArgs> _acceptEventArgsPool = new();
        private const int AcceptEventArgsPoolSize = 10;

        public ushort ListenPort => _listenPort;
        public bool IsIPv4Available { get; private set; }
        public bool IsIPv6Available { get; private set; }
        public bool IsInitialized => _isInitialized;

        private class ConnectionInfoMetadata
        {
            public string CorrelationId { get; set; } = string.Empty;
            public long SetTimestamp { get; set; }
            public ulong ConnectionId { get; set; }
            public ushort Port { get; set; }
            public ushort AddressFamily { get; set; }
        }


        /// <summary>
        /// Store connection info keyed by local port.
        /// </summary>
        public void SetConnInfo(NativeNetFilterApi.NF_TCP_CONN_INFO connInfo, ulong connectionId = 0)
        {
            var timestamp = Stopwatch.GetTimestamp();
            ushort localPort = ExtractPort(connInfo.localAddress, connInfo.ip_family);

            if (localPort > 0)
            {
                _connInfoMap[localPort] = connInfo;
                var correlationId = connectionId > 0 ? $"{connectionId}-{timestamp}" : $"UNK-{timestamp}";
                _connInfoMetadata[localPort] = new ConnectionInfoMetadata
                {
                    CorrelationId = correlationId,
                    SetTimestamp = timestamp,
                    ConnectionId = connectionId,
                    Port = localPort,
                    AddressFamily = connInfo.ip_family
                };
            }
        }

        /// <summary>
        /// Get connection info by remote port.
        /// </summary>
        public bool GetRemoteAddress(IPEndPoint remoteEndPoint, ulong connectionId, out NativeNetFilterApi.NF_TCP_CONN_INFO connInfo)
        {
            ushort port = (ushort)remoteEndPoint.Port;
            bool found = _connInfoMap.TryRemove(port, out connInfo);

            if (!found)
            {
                Log.Warning("[ERROR] GetRemoteAddress FAILED: ConnId={ConnectionId} Port={Port}", connectionId, port);
            }

            return found;
        }

        /// <summary>
        /// Extracts port number from sockaddr structure.
        /// </summary>
        private ushort ExtractPort(byte[] sockAddr, ushort ipFamily)
        {
            if (sockAddr == null || sockAddr.Length < 4)
            {
                return 0;
            }

            ushort portNetwork = BitConverter.ToUInt16(sockAddr, 2);
            return (ushort)IPAddress.NetworkToHostOrder((short)portNetwork);
        }

        /// <summary>
        /// Initializes the local TCP proxy server.
        /// </summary>
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

            InitializeAcceptEventArgsPool();

            try
            {
                try
                {
                    _ipv4ListenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    _ipv4ListenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    _ipv4ListenSocket.Bind(new IPEndPoint(IPAddress.Loopback, port));
                    _ipv4ListenSocket.Listen(1024);
                    StartAccept(_ipv4ListenSocket, AddressFamily.InterNetwork);
                    IsIPv4Available = true;
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "LocalTcpProxy: Failed to start IPv4 listener");
                }

                try
                {
                    _ipv6ListenSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                    _ipv6ListenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    _ipv6ListenSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                    _ipv6ListenSocket.Bind(new IPEndPoint(IPAddress.IPv6Loopback, port));
                    _ipv6ListenSocket.Listen(1024);
                    StartAccept(_ipv6ListenSocket, AddressFamily.InterNetworkV6);
                    IsIPv6Available = true;
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

                _poolMaintenanceTask = Task.Factory.StartNew(
                    async () => await MaintainConnectionPoolAsync(_cancellationTokenSource.Token),
                    _cancellationTokenSource.Token,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default).Unwrap();

                _ = PreWarmConnectionAsync();

                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "LocalTcpProxy: Initialization failed");
                Dispose();
                return false;
            }
        }

        private void InitializeAcceptEventArgsPool()
        {
            for (int i = 0; i < AcceptEventArgsPoolSize; i++)
            {
                var eventArgs = new SocketAsyncEventArgs();
                eventArgs.Completed += ProcessAccept;
                _acceptEventArgsPool.Enqueue(eventArgs);
            }
        }

        private void StartAccept(Socket listenSocket, AddressFamily ipFamily)
        {
            if (!_acceptEventArgsPool.TryDequeue(out var acceptEventArgs))
            {
                acceptEventArgs = new SocketAsyncEventArgs();
                acceptEventArgs.Completed += ProcessAccept;
            }

            acceptEventArgs.UserToken = new AcceptContext { ListenSocket = listenSocket, IpFamily = ipFamily };
            acceptEventArgs.AcceptSocket = null;

            if (!listenSocket.AcceptAsync(acceptEventArgs))
            {
                ProcessAccept(null, acceptEventArgs);
            }
        }

        private class AcceptContext
        {
            public Socket ListenSocket { get; set; } = null!;
            public AddressFamily IpFamily { get; set; }
        }

        private void ProcessAccept(object? sender, SocketAsyncEventArgs e)
        {
            var context = (AcceptContext?)e.UserToken;
            if (context == null)
            {
                Log.Error("[ACCEPT-ASYNC] Accept context is null");
                return;
            }

            var listenSocket = context.ListenSocket;
            var ipFamily = context.IpFamily;

            try
            {
                if (e.SocketError == SocketError.Success)
                {
                    var acceptSocket = e.AcceptSocket;
                    if (acceptSocket != null)
                    {
                        var remoteEndPoint = acceptSocket.RemoteEndPoint as IPEndPoint;

                        if (remoteEndPoint != null)
                        {
                            var connectionId = Interlocked.Increment(ref _nextConnectionId);
                            var client = new TcpClient { Client = acceptSocket };
                            var connection = new TcpProxyConnection(connectionId, client, ipFamily, remoteEndPoint, _socks5Target!, _socks5Username, _socks5Password, this);
                            _connections[connectionId] = connection;
                            _ = HandleConnectionAsync(connection, _cancellationTokenSource.Token);
                        }
                        else
                        {
                            Log.Warning("[ACCEPT-ASYNC] Null remote endpoint, closing socket");
                            acceptSocket.Close();
                        }
                    }
                }
                else if (e.SocketError == SocketError.OperationAborted)
                {
                    return;
                }
                else
                {
                    Log.Warning("[ACCEPT-ASYNC] Accept failed: {Error}", e.SocketError);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[ACCEPT-ASYNC] Exception processing accept");
            }
            finally
            {
                e.AcceptSocket = null;
                if (!_cancellationTokenSource.Token.IsCancellationRequested && listenSocket != null)
                {
                    StartAccept(listenSocket, ipFamily);
                }
                else
                {
                    _acceptEventArgsPool.Enqueue(e);
                }
            }
        }


        private async Task PreWarmConnectionAsync()
        {
            try
            {
                if (_cancellationTokenSource.Token.IsCancellationRequested || _socks5Target == null)
                    return;

                var (testClient, testStream) = await Socks5ConnectionHelper.CreateOptimizedConnectionAsync(_socks5Target, timeoutMs: 200);
                try
                {
                    testStream?.Close();
                    testClient?.Close();
                }
                catch { }
            }
            catch { }
        }

        /// <summary>
        /// Gets a pre-authenticated SOCKS5 connection from pool, or creates a new one if pool is empty.
        /// </summary>
        internal async Task<(TcpClient client, NetworkStream stream, bool isPreAuthenticated)> GetSocks5ConnectionAsync()
        {
            if (_connectionPool.TryDequeue(out var pooledConnection))
            {
                if (pooledConnection.Client.Connected &&
                    DateTime.UtcNow - pooledConnection.CreatedAt < TimeSpan.FromSeconds(MaxConnectionAgeSeconds))
                {
                    return (pooledConnection.Client, pooledConnection.Stream, true);
                }
                else
                {
                    try
                    {
                        pooledConnection.Stream?.Close();
                        pooledConnection.Client?.Close();
                    }
                    catch { }
                }
            }

            var (client, stream) = await Socks5ConnectionHelper.CreateOptimizedConnectionAsync(_socks5Target!, timeoutMs: 200);
            return (client, stream, false);
        }

        private async Task MaintainConnectionPoolAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    CleanStaleConnections();

                    while (_connectionPool.Count < MinPoolSize && !cancellationToken.IsCancellationRequested)
                    {
                        var connection = await CreatePreAuthenticatedConnectionAsync(cancellationToken);
                        if (connection != null)
                        {
                            _connectionPool.Enqueue(connection);
                        }
                        else
                        {
                            await Task.Delay(1000, cancellationToken);
                        }
                    }

                    await Task.Delay(PoolRefreshIntervalMs, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "[POOL] Error maintaining connection pool");
                    await Task.Delay(1000, cancellationToken);
                }
            }
        }

        private void CleanStaleConnections()
        {
            var now = DateTime.UtcNow;
            var staleThreshold = TimeSpan.FromSeconds(MaxConnectionAgeSeconds);
            var tempList = new List<PreAuthenticatedConnection>();

            while (_connectionPool.TryDequeue(out var connection))
            {
                if (now - connection.CreatedAt < staleThreshold && connection.Client.Connected)
                {
                    tempList.Add(connection);
                }
                else
                {
                    try
                    {
                        connection.Stream?.Close();
                        connection.Client?.Close();
                    }
                    catch { }
                }
            }

            foreach (var connection in tempList)
            {
                _connectionPool.Enqueue(connection);
            }
        }

        private async Task<PreAuthenticatedConnection?> CreatePreAuthenticatedConnectionAsync(CancellationToken cancellationToken)
        {
            try
            {
                var (client, stream) = await Socks5ConnectionHelper.CreateOptimizedConnectionAsync(
                    _socks5Target!, timeoutMs: 200, cancellationToken);

                await SendAuthRequestAsync(stream);

                var authResponse = new byte[2];
                using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    readCts.CancelAfter(TimeSpan.FromMilliseconds(100));
                    var bytesRead = await stream.ReadAsync(authResponse, readCts.Token);
                    if (bytesRead < 2 || authResponse[0] != 0x05)
                    {
                        try { stream.Close(); client.Close(); } catch { }
                        return null;
                    }
                }

                if (authResponse[1] == 0x02 && !string.IsNullOrEmpty(_socks5Username))
                {
                    await SendUsernamePasswordAuthAsync(stream);
                    var upAuthResponse = new byte[2];
                    using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        readCts.CancelAfter(TimeSpan.FromMilliseconds(100));
                        var bytesRead = await stream.ReadAsync(upAuthResponse, readCts.Token);
                        if (bytesRead < 2 || upAuthResponse[0] != 0x01 || upAuthResponse[1] != 0x00)
                        {
                            try { stream.Close(); client.Close(); } catch { }
                            return null;
                        }
                    }
                }
                else if (authResponse[1] != 0x00)
                {
                    try { stream.Close(); client.Close(); } catch { }
                    return null;
                }

                return new PreAuthenticatedConnection
                {
                    Client = client,
                    Stream = stream,
                    CreatedAt = DateTime.UtcNow,
                    IsAuthenticated = true
                };
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "[POOL] Failed to create pre-authenticated connection");
                return null;
            }
        }

        private async Task SendAuthRequestAsync(NetworkStream stream)
        {
            byte[] request;
            if (!string.IsNullOrEmpty(_socks5Username))
            {
                request = [0x05, 0x01, 0x02];
            }
            else
            {
                request = [0x05, 0x01, 0x00];
            }
            await stream.WriteAsync(request);
        }

        private async Task SendUsernamePasswordAuthAsync(NetworkStream stream)
        {
            var usernameBytes = System.Text.Encoding.UTF8.GetBytes(_socks5Username!);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(_socks5Password ?? "");

            var request = new byte[3 + usernameBytes.Length + passwordBytes.Length];
            request[0] = 0x01;
            request[1] = (byte)usernameBytes.Length;
            Array.Copy(usernameBytes, 0, request, 2, usernameBytes.Length);
            request[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
            Array.Copy(passwordBytes, 0, request, 3 + usernameBytes.Length, passwordBytes.Length);

            await stream.WriteAsync(request);
        }

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


        public void Dispose()
        {
            if (!_isInitialized)
                return;

            _cancellationTokenSource.Cancel();

            try
            {
                _ipv4ListenSocket?.Close();
                _ipv4ListenSocket?.Dispose();
            }
            catch { }
            finally
            {
                _ipv4ListenSocket = null;
            }

            try
            {
                _ipv6ListenSocket?.Close();
                _ipv6ListenSocket?.Dispose();
            }
            catch { }
            finally
            {
                _ipv6ListenSocket = null;
            }

            while (_acceptEventArgsPool.TryDequeue(out var eventArgs))
            {
                try
                {
                    eventArgs.Dispose();
                }
                catch { }
            }

            foreach (var connection in _connections.Values)
            {
                connection.Dispose();
            }
            _connections.Clear();
            _connInfoMap.Clear();

            while (_connectionPool.TryDequeue(out var pooledConnection))
            {
                try
                {
                    pooledConnection.Stream?.Close();
                    pooledConnection.Client?.Close();
                }
                catch { }
            }

#pragma warning disable VSTHRD002
            try
            {
                if (_poolMaintenanceTask != null && !_poolMaintenanceTask.IsCompleted)
                {
                    _poolMaintenanceTask.Wait(TimeSpan.FromSeconds(2));
                }
            }
            catch { }
#pragma warning restore VSTHRD002

            _cancellationTokenSource.Dispose();
            _isInitialized = false;
        }
    }

    /// <summary>
    /// Represents a single TCP proxy connection handling SOCKS5 protocol conversion.
    /// </summary>
    internal class TcpProxyConnection(ulong id, TcpClient client, AddressFamily ipFamily, IPEndPoint remoteEndPoint, IPEndPoint socks5Target, string? username, string? password, LocalTcpProxy proxy) : IDisposable
    {
        private readonly ulong _id = id;
        private readonly TcpClient _client = client;
        private readonly AddressFamily _ipFamily = ipFamily;
        private readonly IPEndPoint _remoteEndPoint = remoteEndPoint;
        private readonly IPEndPoint _socks5Target = socks5Target;
        private readonly string? _username = username;
        private readonly string? _password = password;
        private readonly LocalTcpProxy _proxy = proxy;
        private TcpClient? _socks5Client;
        private NetworkStream? _clientStream = client.GetStream();
        private NetworkStream? _socks5Stream;
        private bool _isDisposed = false;


        public ulong Id => _id;

        /// <summary>
        /// Processes the TCP proxy connection.
        /// </summary>
        public async Task ProcessAsync(CancellationToken cancellationToken)
        {
            try
            {
                var clientSocket = _client.Client;
                clientSocket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                clientSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                clientSocket.SendTimeout = 10000;
                clientSocket.ReceiveTimeout = 10000;

                if (!_proxy.GetRemoteAddress(_remoteEndPoint, _id, out var connInfo))
                {
                    return;
                }

                var originalDestination = ExtractOriginalDestination(connInfo);
                if (originalDestination == null)
                {
                    return;
                }

                var (socks5Client, socks5Stream, isPreAuthenticated) = await _proxy.GetSocks5ConnectionAsync();

                _socks5Client = socks5Client;
                _socks5Stream = socks5Stream;

                if (!isPreAuthenticated)
                {
                    await SendAuthRequestAsync();

                    var authResponse = new byte[2];
                    using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        readCts.CancelAfter(TimeSpan.FromMilliseconds(100));
                    var bytesRead = await _socks5Stream.ReadAsync(authResponse, readCts.Token);
                    if (bytesRead < 2 || authResponse[0] != 0x05)
                    {
                        return;
                    }
                }

                var method = authResponse[1];

                if (method == 0x02 && !string.IsNullOrEmpty(_username))
                {
                    await SendUsernamePasswordAuthAsync();

                    using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        readCts.CancelAfter(TimeSpan.FromMilliseconds(100));
                        var bytesRead = await _socks5Stream.ReadAsync(authResponse, readCts.Token);
                        if (bytesRead < 2 || authResponse[0] != 0x01 || authResponse[1] != 0x00)
                        {
                            return;
                        }
                    }
                }
                else if (method != 0x00)
                {
                    return;
                }
                }

                await SendConnectRequestAsync(originalDestination);

                using (var connectReadCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    connectReadCts.CancelAfter(TimeSpan.FromMilliseconds(200));
                    var connectResponse = await ReadConnectResponseAsync(connectReadCts.Token);
                    if (!connectResponse)
                    {
                        return;
                    }
                }

                var clientToSocks5 = RelayDataAsync(_clientStream!, _socks5Stream, cancellationToken);
                var socks5ToClient = RelayDataAsync(_socks5Stream, _clientStream!, cancellationToken);

                await Task.WhenAny(clientToSocks5, socks5ToClient);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "TcpProxyConnection {Id}: Error in ProcessAsync", _id);
            }
        }

        private IPEndPoint? ExtractOriginalDestination(NativeNetFilterApi.NF_TCP_CONN_INFO connInfo)
        {
            try
            {
                ushort addrFamily = BitConverter.ToUInt16(connInfo.remoteAddress, 0);

                if (addrFamily == 2)
                {
                    if (connInfo.remoteAddress.Length < 8)
                        return null;

                    ushort port = BitConverter.ToUInt16(connInfo.remoteAddress, 2);
                    port = (ushort)IPAddress.NetworkToHostOrder((short)port);

                    uint ipAddr = BitConverter.ToUInt32(connInfo.remoteAddress, 4);
                    var ip = new IPAddress(BitConverter.GetBytes(ipAddr));

                    return new IPEndPoint(ip, port);
                }
                else if (addrFamily == 23)
                {
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
                    return null;
                }
            }
            catch
            {
                return null;
            }
        }

        private async Task SendConnectRequestAsync(IPEndPoint destination)
        {
            byte[] request;
            if (destination.AddressFamily == AddressFamily.InterNetwork)
            {
                request = new byte[10];
                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = 0x01;
                var ipBytes = destination.Address.GetAddressBytes();
                Array.Copy(ipBytes, 0, request, 4, 4);
                var portBytes = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)destination.Port));
                Array.Copy(portBytes, 0, request, 8, 2);
            }
            else
            {
                request = new byte[22];
                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = 0x04;
                var ipBytes = destination.Address.GetAddressBytes();
                Array.Copy(ipBytes, 0, request, 4, 16);
                var portBytes = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)destination.Port));
                Array.Copy(portBytes, 0, request, 20, 2);
            }
            await _socks5Stream!.WriteAsync(request);
        }

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
            if (addressType == 0x01)
            {
                responseLength = 10;
            }
            else if (addressType == 0x04)
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

        private async Task SendAuthRequestAsync()
        {
            byte[] request;
            if (!string.IsNullOrEmpty(_username))
            {
                request = [0x05, 0x01, 0x02];
            }
            else
            {
                request = [0x05, 0x01, 0x00];
            }
            await _socks5Stream!.WriteAsync(request);
        }

        private async Task SendUsernamePasswordAuthAsync()
        {
            var usernameBytes = System.Text.Encoding.UTF8.GetBytes(_username!);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(_password ?? "");

            var request = new byte[3 + usernameBytes.Length + passwordBytes.Length];
            request[0] = 0x01;
            request[1] = (byte)usernameBytes.Length;
            Array.Copy(usernameBytes, 0, request, 2, usernameBytes.Length);
            request[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
            Array.Copy(passwordBytes, 0, request, 3 + usernameBytes.Length, passwordBytes.Length);

            await _socks5Stream!.WriteAsync(request);
        }

        /// <summary>
        /// Relays data bidirectionally between client and SOCKS5 streams.
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

            try { _socks5Stream?.Close(); } catch { }
            try { _socks5Client?.Close(); } catch { }
            _socks5Client = null;
            _socks5Stream = null;

            try { _clientStream?.Close(); } catch { }
            try { _client?.Close(); } catch { }
        }
    }
}
