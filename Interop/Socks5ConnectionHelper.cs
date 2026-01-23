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
        /// <param name="timeoutMs">Connection timeout in milliseconds. Default is 200ms for fast localhost connections. Use 0 for default system timeout.</param>
        /// <param name="cancellationToken">Cancellation token to cancel the connection attempt.</param>
        /// <returns>A tuple containing the connected TcpClient and NetworkStream. The stream is created directly from the socket to bypass TcpClient.GetStream() connection checks.</returns>
        /// <exception cref="SocketException">Thrown when connection fails.</exception>
        /// <exception cref="OperationCanceledException">Thrown when operation is cancelled.</exception>
        public static async Task<(TcpClient client, NetworkStream stream)> CreateOptimizedConnectionAsync(
            IPEndPoint target,
            int timeoutMs = 200,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            AddressFamily addressFamily = target.Address.AddressFamily;
            var socket = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                
                if (addressFamily == AddressFamily.InterNetworkV6)
                {
                    socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)IPV6_V6ONLY, 0);
                }

                using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    if (timeoutMs > 0)
                    {
                        connectCts.CancelAfter(timeoutMs);
                    }

                    await socket.ConnectAsync(target, connectCts.Token);
                }

                socket.SendTimeout = 10000;
                socket.ReceiveTimeout = 10000;

                var tcpClient = new TcpClient();
                tcpClient.Client = socket;
                var stream = new NetworkStream(socket, ownsSocket: false);
                
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
        }
    }
}
