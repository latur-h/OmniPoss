using Microsoft.Extensions.Logging;
using OmniPoss.Models;
using OmniPoss.Services;
using OmniPoss.Utilities;
using OmniPoss.Infrastructure.Interop;

namespace OmniPoss.Core
{
    internal class MainController
    {
        // Server and Socks5ClientService is same
        public Socks5ClientService Socks5Server { get; }
        // NetworkFilterController manages kernel driver and redirector
        public NetworkFilterController Controller { get; }

        private readonly string WorkingDir;
        private readonly ILogger<MainController> _logger;
        private readonly SemaphoreSlim Lock = new(1);

        public bool IsRunning { get; private set; }

        public MainController(Socks5ClientService socks5Server, NetworkFilterController controller, ILogger<MainController> logger)
        {
            WorkingDir = Environment.CurrentDirectory;
            _logger = logger;

            _logger.LogInformation("Working directory: {WorkingDir}", WorkingDir);

            Socks5Server = socks5Server;
            Controller = controller;
        }

        public async Task StartAsync()
        {
            _logger.LogInformation("Starting MainController (OmniPoss service)...");
            await Lock.WaitAsync();
            try
            {
                _logger.LogInformation("Resolving SOCKS5 server hostname: {Hostname}...", Socks5Server.Hostname);
                if (await DnsUtils.LookupAsync(Socks5Server.Hostname) == null)
                {
                    _logger.LogError("DNS lookup failed for SOCKS5 server hostname: {Hostname}", Socks5Server.Hostname);
                    throw new Exception("Lookup Server hostname failed");
                }
                _logger.LogInformation("SOCKS5 server hostname resolved successfully: {Hostname}", Socks5Server.Hostname);

                // Pre-cache STUN Server IP to prevent "Wrong STUN Server" errors during NAT type testing.
                // This is a fire-and-forget background task that runs asynchronously without blocking startup.
                // The DNS lookup result is cached in DnsUtils, so subsequent NAT type tests will use the cached IP.
                // Critical: This must run as fire-and-forget to avoid blocking the startup sequence.
                _logger.LogDebug("Pre-caching STUN server IP in background...");
                _ = Task.Run(async () => await DnsUtils.LookupAsync("stun.syncthing.net"));

                _logger.LogInformation("Refreshing DNS cache and adding firewall rules...");
                await Task.WhenAll(Task.Run(NativeMethods.RefreshDNSCache), Task.Run(FirewallUtils.AddOmniPossFwRules));
                _logger.LogDebug("DNS cache refreshed and firewall rules added");

                try
                {
                    // TryReleaseTcpPort(Socks5Server.Port, Socks5Server.Hostname);

                    // Start Mode Controller
                    _logger.LogInformation("Starting NetworkFilterController...");
                    await Controller.StartAsync(Socks5Server);
                    IsRunning = true;
                    _logger.LogInformation("MainController (OmniPoss service) started successfully");
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to start MainController");
                    await StopAsyncInternalAsync();
                    throw;
                }
            }
            finally
            {
                Lock.Release();
            }
        }
        public async Task StopAsync()
        {
            await Lock.WaitAsync();
            try
            {
                await StopAsyncInternalAsync();
            }
            finally
            {
                Lock.Release();
            }
        }

        private async Task StopAsyncInternalAsync()
        {
            _logger.LogInformation("Stopping MainController (OmniPoss service)...");
            try
            {
                //await Socks5Server.StopAsync();
                await Controller.StopAsync();
                IsRunning = false;
                _logger.LogInformation("MainController (OmniPoss service) stopped successfully");
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error during MainController stop");
                throw;
            }
        }

        public static void PortCheck(ushort port, string portName, PortType portType = PortType.Both)
        {
            try
            {
                PortUtils.CheckPort(port, portType);
            }
            catch
            {
                throw new Exception($"The {portName} ({port}) port is in use.");
            }
        }
        public void TryReleaseTcpPort(ushort port, string portName)
        {
            foreach (var p in PortUtils.GetProcessByUsedTcpPort(port))
            {
                var fileName = p.MainModule?.FileName;
                if (fileName == null)
                    continue;

                if (fileName.StartsWith(WorkingDir))
                {
                    p.Kill();
                    p.WaitForExit();
                }
                else
                {
                    throw new Exception($"The {portName} ({port}) port is used by ({p.Id}){fileName}.");
                }
            }

            PortCheck(port, portName, PortType.TCP);
        }
        public Task<NatTypeTestResult> DiscoveryNatTypeAsync(CancellationToken ctx = default)
        {
            return Socks5TestUtils.DiscoveryNatTypeAsync(Socks5Server, ctx);
        }
        public Task<int?> HttpConnectAsync(CancellationToken ctx = default)
        {
            try
            {
                return Socks5TestUtils.HttpConnectAsync(Socks5Server, ctx);
            }
            catch (OperationCanceledException)
            {
                // Cancellation is expected, no need to log
                return Task.FromResult<int?>(null);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "HTTP connect test failed");
                return Task.FromResult<int?>(null);
            }
        }
    }
}
