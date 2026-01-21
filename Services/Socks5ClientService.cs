using OmniPoss.Servers;

namespace OmniPoss.Services
{
    /// <summary>
    /// SOCKS5 client service configuration. Represents the SOCKS5 endpoint that cores expose.
    /// NetFilter acts as a SOCKS5 client connecting to this endpoint (typically provided by sing-box, xray, etc.).
    /// </summary>
    internal class Socks5ClientService(Socks5ClientConfig socks5ClientConfig)
    {
        /// <summary>
        /// Protocol type (always "SOCK5").
        /// </summary>
        public string Type { get; } = "SOCK5";

        /// <summary>
        /// Optional SOCKS5 password for authentication.
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// Optional SOCKS5 username for authentication.
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Remote hostname (unused, kept for compatibility).
        /// </summary>
        public string? RemoteHostname { get; set; }

        /// <summary>
        /// SOCKS5 protocol version (default: "5").
        /// </summary>
        public string Version { get; set; } = "5";

        /// <summary>
        /// SOCKS5 server hostname (typically "127.0.0.1" for local cores).
        /// </summary>
        public string Hostname { get; set; } = socks5ClientConfig.Hostname;

        /// <summary>
        /// SOCKS5 server port (typically 1080 or 1081, must match core's SOCKS5 listen port).
        /// </summary>
        public ushort Port { get; set; } = socks5ClientConfig.Port;

        /// <summary>
        /// Stops the redirector and frees resources.
        /// </summary>
        public Task StopAsync()
        {
            return Interop.Redirector.FreeAsync();
        }
    }
}
