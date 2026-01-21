namespace OmniPoss.Servers
{
    /// <summary>
    /// SOCKS5 client endpoint configuration.
    /// Points to the SOCKS5 server that a core exposes (e.g., sing-box listening on 127.0.0.1:1080).
    /// </summary>
    internal class Socks5ClientConfig
    {
        /// <summary>
        /// SOCKS5 server hostname (default: "127.0.0.1").
        /// </summary>
        public string Hostname { get; set; } = "127.0.0.1";

        /// <summary>
        /// SOCKS5 server port (default: 1080).
        /// Must match the SOCKS5 listen port configured in the core's config file.
        /// </summary>
        public ushort Port { get; set; } = 1080;
    }
}
