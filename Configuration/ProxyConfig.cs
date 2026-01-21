namespace OmniPoss.Configuration
{
    internal readonly struct ProxyConfig(string hostname, ushort port)
    {
        public bool Enabled { get; init; } = true;

        public string Hostname { get; init; } = hostname;
        public ushort Port { get; init; } = port;
    }
}
