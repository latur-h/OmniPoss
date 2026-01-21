using OmniPoss.Servers;

namespace OmniPoss.Configuration
{
    /// <summary>
    /// Root configuration container for the entire application.
    /// Deserialized from data/configs.json.
    /// </summary>
    internal class ApplicationConfig
    {
        /// <summary>
        /// Whether to automatically start the application on system startup.
        /// </summary>
        public bool AutoStart { get; set; } = false;

        /// <summary>
        /// List of external proxy core processes to manage (sing-box, xray, v2ray, etc.).
        /// </summary>
        public List<CoreConfig> Cores { get; set; } = [];

        /// <summary>
        /// SOCKS5 client configuration pointing to the core's SOCKS5 server endpoint.
        /// Must match the SOCKS5 listen address configured in the core's own config file.
        /// </summary>
        public Socks5ClientConfig Socks5ServerConfig { get; set; } = new();

        /// <summary>
        /// Windows system-wide proxy configuration (optional).
        /// </summary>
        public ProxyConfig ProxyConfig { get; set; } = new("127.0.0.1", 1081);

        /// <summary>
        /// Network filter configuration controlling traffic interception and redirection.
        /// </summary>
        public NFConfig NFConfig { get; set; } = new()
        {
            FilterTCP = true,
            FilterUDP = true,
            FilterDNS = true,
            FilterICMP = false,
            FilterIntranet = true,
            FilterLoopback = false,
            FilterParent = true,
            DNSHost = "1.1.1.1:53",
            DNSProxy = true,
            HandleOnlyDNS = true,
            ICMPDelay = 10,
            Bypass = [],
            Handle = []
        };
    }
}
