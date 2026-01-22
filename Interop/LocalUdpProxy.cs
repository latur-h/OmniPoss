using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using OmniPoss.Infrastructure.Interop;
using Serilog;

namespace OmniPoss.Interop
{
    /// <summary>
    /// UDP proxy handler that uses SOCKS5 UDP ASSOCIATE method.
    /// Based on UdpProxy.h from SocksRedirector sample.
    /// </summary>
    /// <remarks>
    /// Initializes a new UDP proxy instance.
    /// </remarks>
    /// <param name="socks5Target">Target SOCKS5 server endpoint.</param>
    /// <param name="username">Optional SOCKS5 username.</param>
    /// <param name="password">Optional SOCKS5 password.</param>
    internal class LocalUdpProxy(IPEndPoint socks5Target, string? username = null, string? password = null) : IDisposable
    {
        private readonly IPEndPoint _socks5Target = socks5Target;
        private readonly string? _username = username;
        private readonly string? _password = password;
        private readonly ConcurrentDictionary<ulong, UdpProxyConnection> _connections = new();
        private bool _isDisposed = false;


        /// <summary>
        /// Create a proxy connection for a UDP endpoint ID.
        /// </summary>
        public bool CreateProxyConnection(ulong id)
        {
            if (_connections.ContainsKey(id))
                return true;

            try
            {
                var connection = new UdpProxyConnection(id, _socks5Target, _username, _password, this);
                if (connection.Initialize())
                {
                    _connections[id] = connection;
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "LocalUdpProxy: Failed to create proxy connection for ID {Id}", id);
            }
            return false;
        }

        /// <summary>
        /// Delete a proxy connection.
        /// </summary>
        public void DeleteProxyConnection(ulong id)
        {
            if (_connections.TryRemove(id, out var connection))
            {
                connection.Dispose();
            }
        }

        /// <summary>
        /// Check if a connection still exists (for race condition protection).
        /// </summary>
        internal bool HasConnection(ulong id)
        {
            return _connections.ContainsKey(id);
        }

        /// <summary>
        /// Send UDP packet through SOCKS5 proxy.
        /// </summary>
        public bool UdpSend(ulong id, byte[] data, int length, IPEndPoint remoteEndPoint, IntPtr options, IntPtr originalRemoteAddress)
        {
            if (!_connections.TryGetValue(id, out var connection))
            {
                if (!CreateProxyConnection(id))
                    return false;
                _connections.TryGetValue(id, out connection);
            }

            if (connection == null)
                return false;

            // Store options and original remote address for posting data back
            connection.StoreOptions(options);
            connection.StoreOriginalRemoteAddress(originalRemoteAddress);

            return connection.Send(data, length, remoteEndPoint);
        }

        /// <summary>
        /// Handle UDP receive callback from UdpProxyConnection when data arrives from relay endpoint.
        /// </summary>
        public void OnUdpReceive(ulong id, byte[] data, int length, IPEndPoint originalDestination)
        {
        }

        public void Dispose()
        {
            if (_isDisposed)
                return;

            _isDisposed = true;
            foreach (var connection in _connections.Values)
            {
                connection.Dispose();
            }
            _connections.Clear();
            Log.Information("LocalUdpProxy: Disposed");
        }
    }

    /// <summary>
    /// Represents a single UDP proxy connection using SOCKS5 UDP ASSOCIATE.
    /// </summary>
    /// <remarks>
    /// Initializes a new UDP proxy connection instance.
    /// </remarks>
    /// <param name="id">Connection ID.</param>
    /// <param name="socks5Target">Target SOCKS5 server endpoint.</param>
    /// <param name="username">Optional SOCKS5 username.</param>
    /// <param name="password">Optional SOCKS5 password.</param>
    /// <param name="proxy">Optional parent LocalUdpProxy instance.</param>
    internal class UdpProxyConnection(ulong id, IPEndPoint socks5Target, string? username, string? password, LocalUdpProxy? proxy = null) : IDisposable
    {
        private readonly ulong _id = id;
        private readonly IPEndPoint _socks5Target = socks5Target;
        private readonly string? _username = username;
        private readonly string? _password = password;
        private TcpClient? _tcpControlClient;
        private NetworkStream? _tcpControlStream;
        private UdpClient? _udpClient;
        private IPEndPoint? _udpRelayEndPoint;
        private bool _isConnected = false;
        private readonly ConcurrentQueue<UdpPacket> _pendingPackets = new();
        /// <summary>
        /// Deep-copied UDP options for posting data back via nf_udpPostReceive.
        /// Original options pointer is only valid during callback context.
        /// </summary>
        private IntPtr _storedOptions = IntPtr.Zero;
        private int _storedOptionsLength = 0;
        private byte[]? _originalRemoteAddressBytes = null;
        private readonly CancellationTokenSource _receiveCancellation = new();
        private readonly LocalUdpProxy? _proxy = proxy; // Reference to parent proxy for callbacks
        private readonly ConcurrentQueue<(IntPtr remoteAddr, IntPtr data)> _pendingBuffers = new();
        private Task? _cleanupTask = null;
        private readonly object _cleanupLock = new object();

        private enum Socks5State
        {
            Auth,
            AuthNegotiation,
            UdpAssociate,
            Connected,
            Error
        }

#pragma warning disable CS0414 // Field is assigned but never used (kept for potential future debugging)
        private Socks5State _state = Socks5State.Auth;

#pragma warning restore CS0414

        /// <summary>
        /// Deep-copy UDP options from NetFilter's udpSend callback.
        /// </summary>
        public void StoreOptions(IntPtr options)
        {
            if (_storedOptions != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_storedOptions);
                _storedOptions = IntPtr.Zero;
                _storedOptionsLength = 0;
            }

            if (options != IntPtr.Zero)
            {
                int flags = Marshal.ReadInt32(options);
                int optionsLength = Marshal.ReadInt32(options + 4);
                int totalSize = 8 + Math.Max(0, optionsLength);

                _storedOptions = Marshal.AllocHGlobal(totalSize);
                _storedOptionsLength = totalSize;
                byte[] optionsBytes = new byte[totalSize];
                Marshal.Copy(options, optionsBytes, 0, totalSize);
                Marshal.Copy(optionsBytes, 0, _storedOptions, totalSize);
            }
        }

        /// <summary>
        /// Stores a copy of the original remote address from NetFilter callback.
        /// </summary>
        public void StoreOriginalRemoteAddress(IntPtr originalRemoteAddress)
        {
            if (originalRemoteAddress != IntPtr.Zero && _originalRemoteAddressBytes == null)
            {
                const int NF_MAX_ADDRESS_LENGTH = 28;
                byte[] addrBytes = new byte[NF_MAX_ADDRESS_LENGTH];
                Marshal.Copy(originalRemoteAddress, addrBytes, 0, NF_MAX_ADDRESS_LENGTH);
                _originalRemoteAddressBytes = addrBytes;
            }
        }

        /// <summary>
        /// Initializes UDP proxy connection by establishing TCP control channel and performing SOCKS5 UDP ASSOCIATE.
        /// </summary>
        /// <returns>True if initialization started successfully, false otherwise.</returns>
        public bool Initialize()
        {
            try
            {
                _ = InitializeAsync();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "UdpProxyConnection {Id}: Initialization failed", _id);
                return false;
            }
        }

        /// <summary>
        /// Asynchronously establishes TCP control connection and starts SOCKS5 UDP ASSOCIATE handshake.
        /// </summary>
        private async Task InitializeAsync()
        {
            try
            {
                // Use optimized connection method (5 second timeout for control channel)
                var (client, stream) = await Socks5ConnectionHelper.CreateOptimizedConnectionAsync(_socks5Target, timeoutMs: 5000);
                _tcpControlClient = client;
                
                // Socket options are already set by the helper, but we can verify/override if needed
                var socket = _tcpControlClient.Client;
                // Helper already sets NoDelay, KeepAlive, and timeouts, but we ensure they're correct
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                
                _tcpControlStream = stream;

                await ProcessUdpAssociateAsync();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "UdpProxyConnection {Id}: Async initialization failed", _id);
                _isConnected = false;
            }
        }

        /// <summary>
        /// Processes SOCKS5 UDP ASSOCIATE handshake: auth, UDP ASSOCIATE request, and starts packet relay.
        /// </summary>
        private async Task ProcessUdpAssociateAsync()
        {
            try
            {
                _state = Socks5State.Auth;
                await SendAuthRequestAsync();

                var authResponse = new byte[2];
                using (var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(1)))
                {
                    var bytesRead = await _tcpControlStream!.ReadAsync(authResponse, readCts.Token);
                    if (bytesRead < 2 || authResponse[0] != 0x05)
                    {
                        Log.Warning("UdpProxyConnection {Id}: Invalid auth response", _id);
                        return;
                    }
                }

                var method = authResponse[1];

                if (method == 0x02 && !string.IsNullOrEmpty(_username))
                {
                    _state = Socks5State.AuthNegotiation;
                    await SendUsernamePasswordAuthAsync();

                    using (var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(1)))
                    {
                        var bytesRead = await _tcpControlStream.ReadAsync(authResponse, readCts.Token);
                        if (bytesRead < 2 || authResponse[0] != 0x01 || authResponse[1] != 0x00)
                        {
                            Log.Warning("UdpProxyConnection {Id}: Username/password auth failed", _id);
                            return;
                        }
                    }
                }
                else if (method != 0x00)
                {
                    Log.Warning("UdpProxyConnection {Id}: Unsupported auth method {Method}", _id, method);
                    return;
                }

                _state = Socks5State.UdpAssociate;
                await SendUdpAssociateRequestAsync();

                IPEndPoint? response;
                using (var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(2)))
                {
                    response = await ReadUdpAssociateResponseAsync(readCts.Token);
                    if (response == null)
                    {
                        Log.Warning("UdpProxyConnection {Id}: UDP ASSOCIATE failed", _id);
                        return;
                    }
                }

                _udpRelayEndPoint = response;
                _udpClient = new UdpClient();
                
                var udpSocket = _udpClient.Client;
                udpSocket.SendTimeout = 10000;
                udpSocket.ReceiveTimeout = 10000;
                
                _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
                _isConnected = true;
                _state = Socks5State.Connected;


                while (_pendingPackets.TryDequeue(out var packet))
                {
                    Send(packet.Data, packet.Length, packet.RemoteEndPoint);
                }

                _ = ReceiveUdpPacketsAsync();

                lock (_cleanupLock)
                {
                    if (_cleanupTask == null)
                    {
                        _cleanupTask = CleanupBuffersAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "UdpProxyConnection {Id}: Error in ProcessUdpAssociateAsync", _id);
            }
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
            await _tcpControlStream!.WriteAsync(request);
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

            await _tcpControlStream!.WriteAsync(request);
        }

        /// <summary>
        /// Sends SOCKS5 UDP ASSOCIATE request to establish UDP relay.
        /// </summary>
        private async Task SendUdpAssociateRequestAsync()
        {
            // UDP ASSOCIATE request with IPv4 (0.0.0.0:0)
            var request = new byte[10];
            request[0] = 0x05; // Version
            request[1] = 0x03; // UDP ASSOCIATE
            request[2] = 0x00; // Reserved
            request[3] = 0x01; // IPv4 address type
            // Address: 0.0.0.0 (already zeros)
            // Port: 0 (already zeros)
            await _tcpControlStream!.WriteAsync(request);
        }

        /// <summary>
        /// Reads SOCKS5 UDP ASSOCIATE response and extracts relay endpoint.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for timeout handling.</param>
        /// <returns>Relay endpoint or null if response is invalid.</returns>
        private async Task<IPEndPoint?> ReadUdpAssociateResponseAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[10];
            var bytesRead = await _tcpControlStream!.ReadAsync(buffer, cancellationToken);
            if (bytesRead < 10 || buffer[0] != 0x05 || buffer[1] != 0x00)
            {
                return null;
            }

            var addressType = buffer[3];
            if (addressType == 0x01)
            {
                var ip = new IPAddress(new byte[] { buffer[4], buffer[5], buffer[6], buffer[7] });
                var port = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 8));
                return new IPEndPoint(ip, port);
            }
            return null;
        }

        /// <summary>
        /// Sends UDP packet to SOCKS5 relay wrapped in SOCKS5 UDP format.
        /// </summary>
        public bool Send(byte[] data, int length, IPEndPoint remoteEndPoint)
        {
            if (!_isConnected || _udpClient == null || _udpRelayEndPoint == null)
            {
                _pendingPackets.Enqueue(new UdpPacket { Data = data, Length = length, RemoteEndPoint = remoteEndPoint });
                return true;
            }

            try
            {
                byte[] wrappedPacket;
                if (remoteEndPoint.AddressFamily == AddressFamily.InterNetwork)
                {
                    wrappedPacket = new byte[10 + length];
                    wrappedPacket[0] = 0x00; // Reserved
                    wrappedPacket[1] = 0x00; // Reserved
                    wrappedPacket[2] = 0x00; // Fragment
                    wrappedPacket[3] = 0x01; // IPv4 address type
                    var ipBytes = remoteEndPoint.Address.GetAddressBytes();
                    Array.Copy(ipBytes, 0, wrappedPacket, 4, 4);
                    var portBytes = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)remoteEndPoint.Port));
                    Array.Copy(portBytes, 0, wrappedPacket, 8, 2);
                    Array.Copy(data, 0, wrappedPacket, 10, length);
                }
                else
                {
                    return false;
                }

                _udpClient.Send(wrappedPacket, wrappedPacket.Length, _udpRelayEndPoint);
                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "UdpProxyConnection {Id}: Error sending UDP packet", _id);
                return false;
            }
        }

        /// <summary>
        /// Placeholder for handling received UDP packets from NetFilter.
        /// </summary>
        public void HandleReceive(byte[] data, int length, IPEndPoint remoteEndPoint)
        {
        }

        /// <summary>
        /// Receives UDP packets from SOCKS5 relay, unwraps SOCKS5 UDP header, and posts back to NetFilter.
        /// Extracts original destination from SOCKS5 header and uses stored options for nf_udpPostReceive.
        /// </summary>
        private async Task ReceiveUdpPacketsAsync()
        {
            if (_udpClient == null || _udpRelayEndPoint == null)
                return;

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_receiveCancellation.Token);

                while (_isConnected && !cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Use cancellation token to allow graceful shutdown
                        var receiveTask = _udpClient.ReceiveAsync();
                        var result = await receiveTask.WaitAsync(cts.Token);

                        if (result.Buffer.Length < 4)
                            continue;

                        if (result.Buffer[0] != 0x00 || result.Buffer[1] != 0x00)
                            continue;

                        byte atyp = result.Buffer[3];
                        int headerSize;
                        IPEndPoint? originalDestination = null;
                        byte[]? remoteAddressBytes = null;

                        if (atyp == 0x01 && result.Buffer.Length >= 10)
                        {
                            headerSize = 10;
                            uint address = BitConverter.ToUInt32(result.Buffer, 4);
                            ushort port = BitConverter.ToUInt16(result.Buffer, 8);

                            var ipBytes = BitConverter.GetBytes(address);
                            Array.Reverse(ipBytes);
                            var ip = new IPAddress(ipBytes);
                            var portHost = (ushort)IPAddress.NetworkToHostOrder((short)port);
                            originalDestination = new IPEndPoint(ip, portHost);

                            remoteAddressBytes = new byte[16];
                            remoteAddressBytes[0] = 2;
                            remoteAddressBytes[1] = 0;
                            BitConverter.GetBytes(port).CopyTo(remoteAddressBytes, 2);
                            BitConverter.GetBytes(address).CopyTo(remoteAddressBytes, 4);
                        }
                        else if (atyp == 0x04 && result.Buffer.Length >= 22)
                        {
                            headerSize = 22;
                            byte[] ipBytes = new byte[16];
                            Array.Copy(result.Buffer, 4, ipBytes, 0, 16);
                            ushort port = BitConverter.ToUInt16(result.Buffer, 20);

                            var ip = new IPAddress(ipBytes);
                            var portHost = (ushort)IPAddress.NetworkToHostOrder((short)port);
                            originalDestination = new IPEndPoint(ip, portHost);

                            remoteAddressBytes = new byte[28];
                            remoteAddressBytes[0] = 23;
                            remoteAddressBytes[1] = 0;
                            BitConverter.GetBytes(port).CopyTo(remoteAddressBytes, 2);
                            Array.Copy(ipBytes, 0, remoteAddressBytes, 8, 16);
                        }
                        else
                        {
                            continue;
                        }

                        if (originalDestination == null || remoteAddressBytes == null)
                            continue;

                        int dataLength = result.Buffer.Length - headerSize;
                        if (dataLength <= 0)
                            continue;

                        byte[] data = new byte[dataLength];
                        Array.Copy(result.Buffer, headerSize, data, 0, dataLength);

                        if (!_isConnected)
                        {
                            continue;
                        }

                        IntPtr remoteAddrPtr = Marshal.AllocHGlobal(remoteAddressBytes.Length);
                        IntPtr dataPtr = Marshal.AllocHGlobal(dataLength);
                        try
                        {
                            Marshal.Copy(remoteAddressBytes, 0, remoteAddrPtr, remoteAddressBytes.Length);
                            Marshal.Copy(data, 0, dataPtr, dataLength);

                            IntPtr optionsPtr = _storedOptions;

                            if (!_isConnected || (_proxy != null && !_proxy.HasConnection(_id)))
                            {
                                Marshal.FreeHGlobal(remoteAddrPtr);
                                Marshal.FreeHGlobal(dataPtr);
                                continue;
                            }

                            var status = NativeNetFilterApi.nf_udpPostReceive(_id, remoteAddrPtr, dataPtr, dataLength, optionsPtr);
                            if (status == NativeNetFilterApi.NF_STATUS.NF_STATUS_SUCCESS)
                            {
                                _pendingBuffers.Enqueue((remoteAddrPtr, dataPtr));
                                remoteAddrPtr = IntPtr.Zero;
                                dataPtr = IntPtr.Zero;
                            }
                            else
                            {
                                if (status == NativeNetFilterApi.NF_STATUS.NF_STATUS_INVALID_ENDPOINT_ID)
                                {
                                    _isConnected = false;
                                }
                                else if (_isConnected)
                                {
                                    Log.Warning("UdpProxyConnection {Id}: nf_udpPostReceive failed with status {Status}", _id, status);
                                }
                                Marshal.FreeHGlobal(remoteAddrPtr);
                                Marshal.FreeHGlobal(dataPtr);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex, "UdpProxyConnection {Id}: Error posting data to NetFilter", _id);
                            if (remoteAddrPtr != IntPtr.Zero) Marshal.FreeHGlobal(remoteAddrPtr);
                            if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected when connection is closed
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        // UDP client was disposed, exit gracefully
                        break;
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted || ex.SocketErrorCode == SocketError.Interrupted)
                    {
                        // Operation was cancelled, exit gracefully
                        break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when connection is closed
            }
            catch (Exception ex) when (ex is ObjectDisposedException ||
                                       (ex is SocketException se && (se.SocketErrorCode == SocketError.OperationAborted || se.SocketErrorCode == SocketError.Interrupted)))
            {
            }
            catch (Exception ex)
            {
                if (_isConnected)
                {
                    Log.Error(ex, "UdpProxyConnection {Id}: Error receiving UDP packets", _id);
                }
            }
        }

        /// <summary>
        /// Background task that cleans up pending buffers after NetFilter has processed them.
        /// </summary>
        private async Task CleanupBuffersAsync()
        {
            try
            {
                while (_isConnected && !_receiveCancellation.Token.IsCancellationRequested)
                {
                    await Task.Delay(500, _receiveCancellation.Token);

                    if (_pendingBuffers.TryDequeue(out var buffer))
                    {
                        try
                        {
                            Marshal.FreeHGlobal(buffer.remoteAddr);
                            Marshal.FreeHGlobal(buffer.data);
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "UdpProxyConnection {Id}: Error freeing buffer", _id);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                Log.Error(ex, "UdpProxyConnection {Id}: Error in cleanup task", _id);
            }
        }

        public void Dispose()
        {
            _isConnected = false;
            _receiveCancellation.Cancel();

            try
            {
                _cleanupTask?.Wait(TimeSpan.FromSeconds(1));
            }
            catch { }

            try { _tcpControlStream?.Close(); } catch { }
            try { _tcpControlClient?.Close(); } catch { }
            try { _udpClient?.Close(); } catch { }

            while (_pendingBuffers.TryDequeue(out var buffer))
            {
                try
                {
                    Marshal.FreeHGlobal(buffer.remoteAddr);
                    Marshal.FreeHGlobal(buffer.data);
                }
                catch { }
            }

            if (_storedOptions != IntPtr.Zero)
            {
                try
                {
                    Marshal.FreeHGlobal(_storedOptions);
                }
                catch { }
                _storedOptions = IntPtr.Zero;
                _storedOptionsLength = 0;
            }

            _receiveCancellation.Dispose();
        }

        private struct UdpPacket
        {
            public byte[] Data;
            public int Length;
            public IPEndPoint RemoteEndPoint;
        }
    }
}
