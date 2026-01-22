using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using OmniPoss.Infrastructure.Interop;
using Serilog;
using static OmniPoss.Infrastructure.Interop.NativeMethods;

namespace OmniPoss.Interop
{
    /// <summary>
    /// Helper class for creating optimized SOCKS5 connections using WSAConnectByNameW.
    /// This provides Windows-specific optimizations matching the original Redirector implementation.
    /// </summary>
    internal static class Socks5ConnectionHelper
    {
        /// <summary>
        /// Creates a TCP connection to the specified endpoint using WSAConnectByNameW for optimized performance.
        /// This matches the original Redirector implementation and provides better performance than TcpClient.ConnectAsync.
        /// </summary>
        /// <param name="target">Target endpoint to connect to.</param>
        /// <param name="timeoutMs">Connection timeout in milliseconds. Default is 5000ms (5 seconds). Use 0 for default system timeout.</param>
        /// <param name="cancellationToken">Cancellation token to cancel the connection attempt.</param>
        /// <returns>A tuple containing the connected TcpClient and NetworkStream. The stream is created directly from the socket to bypass TcpClient.GetStream() connection checks.</returns>
        /// <exception cref="SocketException">Thrown when connection fails.</exception>
        /// <exception cref="OperationCanceledException">Thrown when operation is cancelled.</exception>
        public static async Task<(TcpClient client, NetworkStream stream)> CreateOptimizedConnectionAsync(
            IPEndPoint target,
            int timeoutMs = 5000,
            CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Create socket using AF_INET6 to support both IPv4 and IPv6 (like original Redirector)
                var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    // Disable IPV6_V6ONLY to allow IPv4 connections through IPv6 socket (like original)
                    socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)IPV6_V6ONLY, 0);

                    // Set SO_REUSEADDR (like original Redirector)
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                    // Set TCP_NODELAY and KEEPALIVE
                    socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

                    // Use WSAConnectByNameW for optimized connection (combines DNS resolution + connection)
                    string nodeName = target.Address.ToString();
                    string serviceName = target.Port.ToString();

                    uint localAddrLen = 0;
                    uint remoteAddrLen = 0;

                    // Prepare timeout structure if timeout is specified
                    IntPtr timeoutPtr = IntPtr.Zero;
                    Timeval timeout = default;
                    if (timeoutMs > 0)
                    {
                        timeout = new Timeval
                        {
                            tv_sec = timeoutMs / 1000,
                            tv_usec = (timeoutMs % 1000) * 1000 // Convert milliseconds to microseconds
                        };
                        timeoutPtr = Marshal.AllocHGlobal(Marshal.SizeOf(timeout));
                        Marshal.StructureToPtr(timeout, timeoutPtr, false);
                    }

                    try
                    {
                        // WSAConnectByNameW is blocking, so we run it in a task with timeout
                        bool connected = WSAConnectByNameW(
                            socket.Handle,
                            nodeName,
                            serviceName,
                            ref localAddrLen,
                            IntPtr.Zero, // Don't need local address
                            ref remoteAddrLen,
                            IntPtr.Zero, // Don't need remote address
                            timeoutPtr,  // Timeout (IntPtr.Zero if using default)
                            IntPtr.Zero  // Reserved, must be NULL
                        );

                        if (!connected)
                        {
                            int error = WSAGetLastError();
                            socket.Close();
                            Log.Error("WSAConnectByNameW failed for {Target}: Error {Error}", target, error);
                            
                            // SocketException constructor automatically maps Windows error codes to SocketErrorCode
                            // Common mappings:
                            // 10060 (WSAETIMEDOUT) -> SocketError.TimedOut
                            // 10051 (WSAENETUNREACH) -> SocketError.NetworkUnreachable
                            // 10049 (WSAEADDRNOTAVAIL) -> SocketError.AddressNotAvailable
                            throw new SocketException(error);
                        }
                        
                        Log.Debug("WSAConnectByNameW succeeded for {Target}, socket.Connected={Connected}", target, socket.Connected);
                    }
                    finally
                    {
                        if (timeoutPtr != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(timeoutPtr);
                        }
                    }

                    // Set SO_UPDATE_CONNECT_CONTEXT (required after WSAConnectByNameW)
                    // This enables previously set socket options
                    try
                    {
                        socket.SetSocketOption(SocketOptionLevel.Socket, (SocketOptionName)SO_UPDATE_CONNECT_CONTEXT, Array.Empty<byte>());
                        Log.Debug("SO_UPDATE_CONNECT_CONTEXT set successfully for {Target}", target);
                    }
                    catch (SocketException ex)
                    {
                        Log.Warning(ex, "Failed to set SO_UPDATE_CONNECT_CONTEXT for {Target}, continuing anyway", target);
                        // Continue - this might still work
                    }

                    // Set send/receive timeouts using WSAIoctl (like original Redirector: 120s send, 10s receive)
                    var timeoutStruct = new SEND_RECEIVE_TIMEOUT
                    {
                        OnOff = 1,
                        SendTimeout = 120000,    // 120 seconds (like original)
                        ReceiveTimeout = 10000   // 10 seconds (like original)
                    };

                    IntPtr timeoutIoctlPtr = Marshal.AllocHGlobal(Marshal.SizeOf(timeoutStruct));
                    try
                    {
                        Marshal.StructureToPtr(timeoutStruct, timeoutIoctlPtr, false);
                        uint bytesReturned;
                        int result = WSAIoctl(
                            socket.Handle,
                            SIO_SET_SEND_RECEIVE_TIMEOUT,
                            timeoutIoctlPtr,
                            (uint)Marshal.SizeOf(timeoutStruct),
                            IntPtr.Zero,
                            0,
                            out bytesReturned,
                            IntPtr.Zero,
                            IntPtr.Zero
                        );

                        if (result != 0)
                        {
                            // If WSAIoctl fails, fall back to standard socket properties
                            Log.Debug("WSAIoctl for send/receive timeout failed, using standard socket properties. Error: {Error}", WSAGetLastError());
                            socket.SendTimeout = 10000;
                            socket.ReceiveTimeout = 10000;
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(timeoutIoctlPtr);
                    }

                    // After WSAConnectByNameW and SO_UPDATE_CONNECT_CONTEXT, the socket is connected at OS level.
                    // However, .NET's Socket.Connected property may not be updated immediately.
                    // NetworkStream constructor checks socket.Connected and will throw if false.
                    // 
                    // Solution: Force .NET to recognize the connection by:
                    // 1. Using reflection to set the internal _isConnected field
                    // 2. Or performing a small I/O operation to update the state
                    // 3. Or using getpeername via P/Invoke to verify and update state
                    
                    // Try to update socket's internal connection state using reflection
                    try
                    {
                        var socketType = typeof(Socket);
                        var isConnectedField = socketType.GetField("_isConnected", 
                            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                        
                        if (isConnectedField != null)
                        {
                            isConnectedField.SetValue(socket, true);
                            Log.Debug("Updated socket._isConnected via reflection for {Target}", target);
                        }
                        else
                        {
                            // Fallback: Try to access RemoteEndPoint which may force state update
                            try
                            {
                                var _ = socket.RemoteEndPoint;
                            }
                            catch { }
                            
                            // If reflection doesn't work, try a zero-byte send in non-blocking mode
                            var wasBlocking = socket.Blocking;
                            try
                            {
                                socket.Blocking = false;
                                // Zero-byte send to update connection state
                                socket.Send(Array.Empty<byte>(), 0, 0, SocketFlags.None);
                                socket.Blocking = wasBlocking;
                            }
                            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock || ex.SocketErrorCode == SocketError.Success)
                            {
                                // WouldBlock or Success means socket is connected
                                socket.Blocking = wasBlocking;
                            }
                            catch
                            {
                                socket.Blocking = wasBlocking;
                                throw;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "Failed to update socket connection state for {Target}, will try NetworkStream anyway", target);
                    }
                    
                    // Wrap the socket in a TcpClient for compatibility
                    var tcpClient = new TcpClient();
                    tcpClient.Client = socket;
                    
                    // Now try to create NetworkStream - it should work if socket.Connected is true
                    NetworkStream stream;
                    try
                    {
                        stream = new NetworkStream(socket, ownsSocket: false);
                        Log.Debug("WSAConnectByNameW connection established: {Target}, NetworkStream created successfully", target);
                    }
                    catch (IOException)
                    {
                        // If NetworkStream still fails, fall back to TcpClient.Connect
                        Log.Warning("NetworkStream creation failed for {Target}, falling back to TcpClient.Connect", target);
                        socket.Close();
                        
                        // Fallback to standard connection method (synchronous, inside Task.Run)
                        var fallbackClient = new TcpClient();
                        fallbackClient.Connect(target.Address, target.Port);
                        stream = fallbackClient.GetStream();
                        return (fallbackClient, stream);
                    }
                    
                    return (tcpClient, stream);
                }
                catch (SocketException)
                {
                    try { socket.Close(); } catch { }
                    throw;
                }
                catch (Exception ex)
                {
                    try { socket.Close(); } catch { }
                    Log.Error(ex, "Failed to create optimized SOCKS5 connection to {Target}", target);
                    throw;
                }
            }, cancellationToken);
        }
    }
}
