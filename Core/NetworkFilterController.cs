using OmniPoss.Configuration;
using OmniPoss.Infrastructure.Drivers;
using OmniPoss.Services;
using OmniPoss.Utilities;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Sockets;
using System.Text;
using static OmniPoss.Interop.Redirector;

namespace OmniPoss.Core
{
    internal class NetworkFilterController
    {
        private readonly NFConfig _mode;
        private readonly RedirectorConfig _rdrConfig;
        private readonly NetworkFilterDriver _driverManager;
        private readonly ILogger<NetworkFilterController> _logger;

        public NetworkFilterController(NFConfig redirector, NetworkFilterDriver driverManager, ILogger<NetworkFilterController> logger)
        {
            _driverManager = driverManager;
            _logger = logger;

            _rdrConfig = new RedirectorConfig()
            {
                DNSHost = "1.1.1.1:53",
                FilterUDP = true,
                FilterTCP = true,
                FilterDNS = true,
                FilterParent = true,
                DNSProxy = true,
                HandleOnlyDNS = true,
                FilterICMP = false,
                ICMPDelay = 10
            };

            _mode = redirector;
            _logger.LogDebug("NetworkFilterController initialized with config: FilterTCP={FilterTCP}, FilterUDP={FilterUDP}, FilterDNS={FilterDNS}, FilterICMP={FilterICMP}",
                _mode.FilterTCP, _mode.FilterUDP, _mode.FilterDNS, _mode.FilterICMP);
        }

        public async Task StartAsync(Socks5ClientService server)
        {
            _logger.LogInformation("Starting NetworkFilterController with SOCKS5 server: {Hostname}:{Port}", server.Hostname, server.Port);

            try
            {
                _logger.LogInformation("Ensuring network filter driver is installed...");
                _driverManager.EnsureDriverInstalled();
                _logger.LogDebug("Driver installation check completed");

                _logger.LogDebug("Configuring filter options...");
                Dial(NameList.AIO_FILTERLOOPBACK, _mode.FilterLoopback);
                _logger.LogDebug("FilterLoopback: {Value}", _mode.FilterLoopback);

                Dial(NameList.AIO_FILTERINTRANET, _mode.FilterIntranet);
                _logger.LogDebug("FilterIntranet: {Value}", _mode.FilterIntranet);

                Dial(NameList.AIO_FILTERPARENT, _mode.FilterParent ?? _rdrConfig.FilterParent);
                _logger.LogDebug("FilterParent: {Value}", _mode.FilterParent ?? _rdrConfig.FilterParent);

                Dial(NameList.AIO_FILTERICMP, _mode.FilterICMP ?? _rdrConfig.FilterICMP);
                bool filterIcmp = _mode.FilterICMP ?? _rdrConfig.FilterICMP;
                _logger.LogDebug("FilterICMP: {Value}", filterIcmp);

                if (filterIcmp)
                {
                    var icmpDelay = (_mode.FilterICMP != null ? _mode.ICMPDelay ?? 10 : _rdrConfig.ICMPDelay).ToString();
                    Dial(NameList.AIO_ICMPING, icmpDelay);
                    _logger.LogDebug("ICMPDelay: {Delay}ms", icmpDelay);
                }

                Dial(NameList.AIO_FILTERTCP, _mode.FilterTCP ?? _rdrConfig.FilterTCP);
                _logger.LogDebug("FilterTCP: {Value}", _mode.FilterTCP ?? _rdrConfig.FilterTCP);

                Dial(NameList.AIO_FILTERUDP, _mode.FilterUDP ?? _rdrConfig.FilterUDP);
                _logger.LogDebug("FilterUDP: {Value}", _mode.FilterUDP ?? _rdrConfig.FilterUDP);

                // DNS
                _logger.LogDebug("Configuring DNS settings...");
                Dial(NameList.AIO_FILTERDNS, _mode.FilterDNS ?? _rdrConfig.FilterDNS);
                bool filterDns = _mode.FilterDNS ?? _rdrConfig.FilterDNS;
                _logger.LogDebug("FilterDNS: {Value}", filterDns);

                Dial(NameList.AIO_DNSONLY, _mode.HandleOnlyDNS ?? _rdrConfig.HandleOnlyDNS);
                _logger.LogDebug("HandleOnlyDNS: {Value}", _mode.HandleOnlyDNS ?? _rdrConfig.HandleOnlyDNS);

                Dial(NameList.AIO_DNSPROX, _mode.DNSProxy ?? _rdrConfig.DNSProxy);
                _logger.LogDebug("DNSProxy: {Value}", _mode.DNSProxy ?? _rdrConfig.DNSProxy);

                if (filterDns)
                {
                    var dnsStr = _mode.FilterDNS != null ? _mode.DNSHost : _rdrConfig.DNSHost;
                    dnsStr = ValueOrDefault(dnsStr) ?? $"1.1.1.1:53";

                    var dns = IPEndPoint.Parse(dnsStr);
                    if (dns.Port == 0)
                        dns.Port = 53;

                    Dial(NameList.AIO_DNSHOST, dns.Address.ToString());
                    Dial(NameList.AIO_DNSPORT, dns.Port.ToString());
                    _logger.LogInformation("DNS server configured: {DnsHost}:{DnsPort}", dns.Address, dns.Port);
                }

                // Server
                _logger.LogInformation("Resolving SOCKS5 server hostname: {Hostname}...", server.Hostname);
                var resolvedHost = await AutoResolveHostnameAsync(server);
                _logger.LogInformation("SOCKS5 server resolved to: {ResolvedHost}:{Port}", resolvedHost, server.Port);

                Dial(NameList.AIO_TGTHOST, resolvedHost);
                Dial(NameList.AIO_TGTPORT, server.Port.ToString());
                Dial(NameList.AIO_TGTUSER, server.Username ?? string.Empty);
                Dial(NameList.AIO_TGTPASS, server.Password ?? string.Empty);
                _logger.LogDebug("SOCKS5 target configured: {Host}:{Port}, Username: {HasUsername}",
                    resolvedHost, server.Port, !string.IsNullOrEmpty(server.Username) ? "Yes" : "No");

                // Mode Rule
                _logger.LogDebug("Configuring bypass and handle rules...");
                DialRule();
                _logger.LogDebug("Rules configured: Bypass={BypassCount}, Handle={HandleCount}",
                    _mode.Bypass?.Count() ?? 0, _mode.Handle?.Count() ?? 0);

                _logger.LogInformation("Initializing redirector...");
                if (!await InitAsync())
                {
                    _logger.LogError("Redirector initialization failed");
                    throw new Exception("Redirector start failed.");
                }
                _logger.LogInformation("NetworkFilterController started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start NetworkFilterController");
                throw;
            }
        }
        public async Task StopAsync()
        {
            _logger.LogInformation("Stopping NetworkFilterController...");
            try
            {
                await FreeAsync();
                _logger.LogInformation("NetworkFilterController stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping NetworkFilterController");
                throw;
            }
        }

        public async Task<string> AutoResolveHostnameAsync(Socks5ClientService server, AddressFamily inet = AddressFamily.Unspecified)
        {
            // ! MainController cached
            return (await DnsUtils.LookupAsync(server.Hostname, inet))!.ToString();
        }

        private bool CheckCppRegex(string r, bool clear = true)
        {
            try
            {
                if (r.StartsWith('!'))
                    return Dial(NameList.AIO_ADDNAME, r[1..]);

                return Dial(NameList.AIO_ADDNAME, r);
            }
            finally
            {
                if (clear)
                    Dial(NameList.AIO_CLRNAME, "");
            }
        }
        public bool CheckRules(IEnumerable<string> rules, out IEnumerable<string> results)
        {
            results = rules.Where(r => !CheckCppRegex(r, false));
            Dial(NameList.AIO_CLRNAME, "");
            return !results.Any();
        }

        private void DialRule()
        {
            Dial(NameList.AIO_CLRNAME, "");
            var invalidList = new List<string>();

            if (_mode.Bypass != null && _mode.Bypass.Any())
            {
                _logger.LogDebug("Configuring {Count} bypass rules", _mode.Bypass.Count());
                foreach (var s in _mode.Bypass)
                {
                    if (!Dial(NameList.AIO_BYPNAME, s))
                    {
                        _logger.LogWarning("Invalid bypass rule: {Rule}", s);
                        invalidList.Add(s);
                    }
                }
            }

            if (_mode.Handle != null && _mode.Handle.Any())
            {
                _logger.LogDebug("Configuring {Count} handle rules", _mode.Handle.Count());
                foreach (var s in _mode.Handle)
                {
                    if (!Dial(NameList.AIO_ADDNAME, s))
                    {
                        _logger.LogWarning("Invalid handle rule: {Rule}", s);
                        invalidList.Add(s);
                    }
                }
            }

            if (invalidList is not null && invalidList.Count > 0)
            {
                _logger.LogError("Invalid rules detected: {InvalidRules}", string.Join(", ", invalidList));
                throw new Exception(string.Join('\n', invalidList));
            }

            // Bypass Self
            var selfBypass = "^" + ToRegexString(Environment.CurrentDirectory);
            Dial(NameList.AIO_BYPNAME, selfBypass);
            _logger.LogDebug("Self-bypass rule configured: {Rule}", selfBypass);
        }

        public string? ValueOrDefault(string? value, string? defaultValue = default)
        {
            return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
        }
        private string ToRegexString(string value)
        {
            var sb = new StringBuilder();
            foreach (var t in value)
            {
                var escapeCharacters = new[] { '\\', '*', '+', '?', '|', '{', '}', '[', ']', '(', ')', '^', '$', '.' };
                if (escapeCharacters.Any(s => s == t))
                    sb.Append('\\');

                sb.Append(t);
            }

            return sb.ToString();
        }
    }
}
