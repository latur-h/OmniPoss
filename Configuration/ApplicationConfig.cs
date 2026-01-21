using OmniPoss.Servers;

namespace OmniPoss.Configuration
{
    internal class ApplicationConfig
    {
        public List<CoreConfig> Cores { get; set; } = [];
        public Socks5ClientConfig Socks5ServerConfig { get; set; } = new();
        public ProxyConfig ProxyConfig { get; set; } = new("127.0.0.1", 1081);
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
