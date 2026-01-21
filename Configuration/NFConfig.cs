namespace OmniPoss.Configuration
{
    /// <summary>
    /// Network filter configuration. Controls which traffic is intercepted and how it's handled.
    /// </summary>
    internal class NFConfig
    {
        /// <summary>
        /// Enables or disables the network filter service.
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Filter ICMP packets. When null, uses default from RedirectorConfig.
        /// </summary>
        public bool? FilterICMP { get; set; }

        /// <summary>
        /// Filter TCP connections. When null, uses default from RedirectorConfig (default: true).
        /// </summary>
        public bool? FilterTCP { get; set; }

        /// <summary>
        /// Filter UDP packets. When null, uses default from RedirectorConfig (default: true).
        /// </summary>
        public bool? FilterUDP { get; set; }

        /// <summary>
        /// Filter DNS queries (port 53). When null, uses default from RedirectorConfig.
        /// </summary>
        public bool? FilterDNS { get; set; }

        /// <summary>
        /// Filter traffic from parent process (current process). When null, uses default from RedirectorConfig.
        /// </summary>
        public bool? FilterParent { get; set; }

        /// <summary>
        /// ICMP delay in milliseconds. When null, uses default from RedirectorConfig.
        /// </summary>
        public int? ICMPDelay { get; set; }

        /// <summary>
        /// Proxy DNS queries through SOCKS5. When null, uses default from RedirectorConfig.
        /// </summary>
        public bool? DNSProxy { get; set; }

        /// <summary>
        /// Only handle DNS traffic (ignore other protocols). When null, uses default from RedirectorConfig.
        /// </summary>
        public bool? HandleOnlyDNS { get; set; }

        /// <summary>
        /// DNS server address in format "host:port" or just "host" (default port: 53). When null, uses default from RedirectorConfig.
        /// </summary>
        public string? DNSHost { get; set; }

        /// <summary>
        /// Filter loopback (127.0.0.1) traffic. Default: false.
        /// </summary>
        public bool FilterLoopback { get; set; } = false;

        /// <summary>
        /// Filter intranet (private network) traffic. Default: true.
        /// </summary>
        public bool FilterIntranet { get; set; } = true;

        /// <summary>
        /// List of regex patterns for processes to bypass (not redirect).
        /// </summary>
        public List<string> Bypass { get; set; } = [];

        /// <summary>
        /// List of regex patterns for processes to handle (redirect). If empty, all processes are handled (when Enabled is true).
        /// </summary>
        public List<string> Handle { get; set; } = [];

        /// <summary>
        /// Local proxy server port (default: 8888). This is the port that the kernel driver redirects intercepted connections to.
        /// </summary>
        public ushort? LocalProxyPort { get; set; }
    }
}
