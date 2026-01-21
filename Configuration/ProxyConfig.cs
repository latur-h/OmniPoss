namespace OmniPoss.Configuration
{
    /// <summary>
    /// Windows system-wide proxy configuration.
    /// Modifies registry settings to configure Windows proxy.
    /// </summary>
    internal readonly struct ProxyConfig(string hostname, ushort port)
    {
        /// <summary>
        /// Whether to enable the system proxy.
        /// </summary>
        public bool Enabled { get; init; } = false;

        /// <summary>
        /// Proxy server hostname (typically "127.0.0.1" for local proxy).
        /// </summary>
        public string Hostname { get; init; } = hostname;

        /// <summary>
        /// Proxy server port (typically matches SOCKS5 server port).
        /// </summary>
        public ushort Port { get; init; } = port;
    }
}
