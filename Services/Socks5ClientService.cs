using OmniPoss.Servers;

namespace OmniPoss.Services
{
    internal class Socks5ClientService(Socks5ClientConfig socks5ClientConfig)
    {
        public string Type { get; } = "SOCK5";

        public string? Password { get; set; }

        public string? Username { get; set; }

        public string? RemoteHostname { get; set; }

        public string Version { get; set; } = "5";

        public string Hostname { get; set; } = socks5ClientConfig.Hostname;

        public ushort Port { get; set; } = socks5ClientConfig.Port;

        public Task StopAsync()
        {
            return Interop.Redirector.FreeAsync();
        }
    }
}
