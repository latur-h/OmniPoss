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
    /// <summary>
    /// Manages network filter redirector configuration and kernel driver initialization.
    /// Configures filtering rules, DNS settings, bypass/handle patterns, and SOCKS5 target endpoint.
    /// </summary>
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

                // Merge NFConfig with RedirectorConfig defaults (NFConfig takes precedence)
                var mergedConfig = new Configuration.NFConfig
                {
                    FilterLoopback = _mode.FilterLoopback,
                    FilterIntranet = _mode.FilterIntranet,
                    FilterParent = _mode.FilterParent ?? _rdrConfig.FilterParent,
                    FilterTCP = _mode.FilterTCP ?? _rdrConfig.FilterTCP,
                    FilterUDP = _mode.FilterUDP ?? _rdrConfig.FilterUDP,
                    FilterDNS = _mode.FilterDNS ?? _rdrConfig.FilterDNS,
                    FilterICMP = _mode.FilterICMP ?? _rdrConfig.FilterICMP,
                    HandleOnlyDNS = _mode.HandleOnlyDNS ?? _rdrConfig.HandleOnlyDNS,
                    DNSProxy = _mode.DNSProxy ?? _rdrConfig.DNSProxy,
                    DNSHost = _mode.DNSHost ?? _rdrConfig.DNSHost,
                    ICMPDelay = _mode.ICMPDelay ?? _rdrConfig.ICMPDelay,
                    LocalProxyPort = _mode.LocalProxyPort, // Use configured port or null (defaults to 8888)
                    Bypass = _mode.Bypass ?? new List<string>(),
                    Handle = _mode.Handle ?? new List<string>()
                };

                // Apply comprehensive configuration from NFConfig
                _logger.LogDebug("Applying NFConfig to Redirector...");
                OmniPoss.Interop.Redirector.ConfigureFromNFConfig(mergedConfig);

                // Server configuration (SOCKS5 target)
                _logger.LogInformation("Resolving SOCKS5 server hostname: {Hostname}...", server.Hostname);
                var resolvedHost = await AutoResolveHostnameAsync(server);
                _logger.LogInformation("SOCKS5 server resolved to: {ResolvedHost}:{Port}", resolvedHost, server.Port);

                Dial(NameList.AIO_TGTHOST, resolvedHost);
                Dial(NameList.AIO_TGTPORT, server.Port.ToString());
                Dial(NameList.AIO_TGTUSER, server.Username ?? string.Empty);
                Dial(NameList.AIO_TGTPASS, server.Password ?? string.Empty);
                
                // Find the process ID of the SOCKS5 server (core process) listening on the target port
                // This is critical for localProxyProcessId to prevent redirect protection from blocking local connections
                try
                {
                    var processes = PortUtils.GetProcessByUsedTcpPort(server.Port).ToList();
                    if (processes.Count > 0)
                    {
                        var processId = (uint)processes[0].Id;
                        Dial(NameList.AIO_TGTPROCESSID, processId.ToString());
                        _logger.LogInformation("Found SOCKS5 server process ID: {ProcessId} (listening on port {Port})", processId, server.Port);
                    }
                    else
                    {
                        _logger.LogWarning("Could not find process listening on SOCKS5 port {Port}. Redirect protection may block connections.", server.Port);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to get process ID for SOCKS5 port {Port}. Redirect protection may block connections.", server.Port);
                }
                
                _logger.LogDebug("SOCKS5 target configured: {Host}:{Port}, Username: {HasUsername}",
                    resolvedHost, server.Port, !string.IsNullOrEmpty(server.Username) ? "Yes" : "No");

                // Add self-bypass rule (from original DialRule method)
                var selfBypass = "^" + ToRegexString(Environment.CurrentDirectory);
                Dial(NameList.AIO_BYPNAME, selfBypass);
                _logger.LogDebug("Self-bypass rule configured: {Rule}", selfBypass);

                _logger.LogInformation("Initializing redirector...");
                try
                {
                    if (!await InitAsync())
                    {
                        _logger.LogError("Redirector initialization returned false");
                        throw new Exception("Redirector start failed.");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Redirector initialization failed with exception");
                    throw;
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
