using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OmniPoss.Configuration;
using OmniPoss.Infrastructure.Process;
using OmniPoss.Services;
using OmniPoss.Servers;
using OmniPoss.UI.Tray;
using System.Collections.Concurrent;
using Newtonsoft.Json;
using System.IO;

namespace OmniPoss.Core
{
    /// <summary>
    /// Central orchestrator for the entire application lifecycle.
    /// Manages dependency injection, component initialization, hot-reload, system tray menu, and graceful shutdown.
    /// </summary>
    internal class ApplicationHost(IServiceProvider serviceProvider) : IDisposable
    {
        private readonly IServiceProvider _serviceProvider = serviceProvider;
        private readonly ApplicationConfig _config = serviceProvider.GetRequiredService<ApplicationConfig>();
        private readonly CoreProcessManager _coreManager = serviceProvider.GetRequiredService<CoreProcessManager>();
        private readonly MainController _mainController = serviceProvider.GetRequiredService<MainController>();
        private readonly ProxyService _proxyService = serviceProvider.GetRequiredService<ProxyService>();
        private readonly TrayMenu _trayMenu = serviceProvider.GetRequiredService<TrayMenu>();
        private readonly ILogger<ApplicationHost> _logger = serviceProvider.GetRequiredService<ILogger<ApplicationHost>>();
        private NotifyIcon? _trayIcon;
        private readonly CancellationTokenSource _shutdownCts = new();
        private readonly ConcurrentBag<Task> _backgroundTasks = [];
        private static readonly string ConfigPath = Path.Combine(Path.GetFullPath(Path.Combine("data")), "configs.json");

        /// <summary>
        /// Initializes and starts all enabled components.
        /// </summary>
        public Task InitializeAsync()
        {
            var cancellationToken = _shutdownCts.Token;

            var cores = _serviceProvider.GetRequiredService<List<CoreConfig>>();
            foreach (var core in cores.Where(c => c.Enabled))
            {
                var task = Task.Run(async () =>
                {
                    try
                    {
                        await _coreManager.LaunchAsync(core);
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogInformation("[{CoreKey}] Core launch cancelled", core.Key);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[{CoreKey}] Failed to launch core", core.Key);
                    }
                }, cancellationToken);
                _backgroundTasks.Add(task);
            }

            if (_config.NFConfig.Enabled)
            {
                _logger.LogInformation("OmniPoss service is enabled in config, starting MainController...");
                var task = Task.Run(async () =>
                {
                    try
                    {
                        await _mainController.StartAsync();
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogInformation("MainController start cancelled");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start MainController during initialization");
                    }
                }, cancellationToken);
                _backgroundTasks.Add(task);
            }
            else
            {
                _logger.LogInformation("OmniPoss service is disabled in config, skipping MainController start");
            }

            // Sync proxy state: enable if in config, disable if in registry but not in config
            _logger.LogInformation("Checking proxy state on startup...");
            bool registryProxyEnabled = _proxyService.CheckRegistryState();
            _logger.LogInformation("Proxy registry state: {State}, Config enabled: {ConfigEnabled}",
                registryProxyEnabled ? "Enabled" : "Disabled", _config.ProxyConfig.Enabled);

            if (_config.ProxyConfig.Enabled)
            {
                _logger.LogInformation("Proxy is enabled in config, enabling proxy service...");
                _proxyService.Enable(_config.ProxyConfig);
            }
            else if (registryProxyEnabled)
            {
                // Clean up proxy state from previous run
                _logger.LogInformation("Proxy is enabled in registry but disabled in config. Cleaning up proxy from previous run...");
                _proxyService.Disable();
                _logger.LogInformation("Proxy cleanup completed");
            }
            else
            {
                _logger.LogInformation("Proxy is disabled in both registry and config, no action needed");
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Creates and configures the system tray menu.
        /// </summary>
        public NotifyIcon CreateTrayIcon()
        {
            var cores = _serviceProvider.GetRequiredService<List<CoreConfig>>();
            // Pass function to check actual running state of cores
            var trayMenu = _trayMenu.Init(cores, _config.NFConfig.Enabled, _config.ProxyConfig.Enabled, _config.AutoStart, 
                (key) => _coreManager.IsRunning(key));

            // Attach event handlers
            if (trayMenu.Items["NF"] is ToolStripMenuItem nfItem)
            {
                nfItem.Click += (s, e) =>
                {
                    _logger.LogInformation("NF menu item clicked - starting toggle operation");
                    var task = Task.Run(async () =>
                    {
                        try
                        {
                            _logger.LogInformation("ToggleNetFilterAsync task started");
                            await ToggleNetFilterAsync();
                            _logger.LogInformation("ToggleNetFilterAsync task completed successfully");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Unhandled exception in ToggleNetFilterAsync background task: {Exception}", ex);
                            _logger.LogError(ex, "Exception details - Type: {Type}, Message: {Message}, StackTrace: {StackTrace}",
                                ex.GetType().Name, ex.Message, ex.StackTrace);
                            // Don't rethrow - we don't want background task exceptions to crash the app
                        }
                    }, _shutdownCts.Token);
                    _backgroundTasks.Add(task);
                    _logger.LogInformation("NF toggle task added to background tasks");
                };
            }
            if (trayMenu.Items["Proxy"] is ToolStripMenuItem proxyItem)
            {
                proxyItem.Click += (s, e) => ToggleProxy();
            }
            if (trayMenu.Items["Console"] is ToolStripMenuItem consoleItem)
            {
                consoleItem.Click += (s, e) => ToggleConsole();
            }
            if (trayMenu.Items["OpenConfigFolder"] is ToolStripMenuItem openConfigItem)
            {
                openConfigItem.Click += (s, e) => OpenConfigFolder();
            }
            if (trayMenu.Items["OpenCoresFolder"] is ToolStripMenuItem openCoresItem)
            {
                openCoresItem.Click += (s, e) => OpenCoresFolder();
            }
            if (trayMenu.Items["Reload"] is ToolStripMenuItem reloadItem)
            {
                reloadItem.Click += (s, e) =>
                {
                    var task = Task.Run(async () => await ReloadAsync(), _shutdownCts.Token);
                    _backgroundTasks.Add(task);
                };
            }
            if (trayMenu.Items["StartWithWindows"] is ToolStripMenuItem startWithWindowsItem)
            {
                startWithWindowsItem.Click += (s, e) =>
                {
                    var task = Task.Run(async () => await ToggleStartupAsync(), _shutdownCts.Token);
                    _backgroundTasks.Add(task);
                };
            }
            if (trayMenu.Items["Exit"] is ToolStripMenuItem exitItem)
            {
                exitItem.Click += (s, e) => _ = ExitApplicationAsync();
            }

            // Attach core toggle handlers
            if (trayMenu.Items["Cores"] is ToolStripMenuItem coresItem)
            {
                foreach (ToolStripMenuItem item in coresItem.DropDownItems.OfType<ToolStripMenuItem>())
                {
                    string? key = item.Name;
                    if (string.IsNullOrEmpty(key)) continue;

                    item.Click += (s, e) =>
                    {
                        var task = Task.Run(async () => await ToggleCoreAsync(key), _shutdownCts.Token);
                        _backgroundTasks.Add(task);
                    };
                }
            }

            _trayIcon = new NotifyIcon
            {
                Text = "OmniPoss",
                Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath),
                ContextMenuStrip = trayMenu,
                Visible = true
            };

            return _trayIcon;
        }

        private async Task ToggleCoreAsync(string key)
        {
            try
            {
                bool isRunning = _coreManager.IsRunning(key);
                if (isRunning)
                {
                    _coreManager.Kill(key);
                }
                else
                {
                    var core = _coreManager.GetCore(key);
                    await _coreManager.LaunchAsync(core);
                }
                _trayMenu.ToggleCore(key, !isRunning);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to toggle core '{CoreKey}'", key);
            }
        }

        private async Task ToggleNetFilterAsync()
        {
            try
            {
                bool wasRunning = _mainController.IsRunning;
                _logger.LogInformation("Toggling OmniPoss service: Current state = {CurrentState}", wasRunning ? "Running" : "Stopped");

                if (wasRunning)
                {
                    _logger.LogInformation("Stopping OmniPoss service via tray menu...");
                    await _mainController.StopAsync();
                    _logger.LogInformation("OmniPoss service stopped successfully via tray menu");
                }
                else
                {
                    _logger.LogInformation("Starting OmniPoss service via tray menu...");
                    await _mainController.StartAsync();
                    _logger.LogInformation("OmniPoss service started successfully via tray menu");
                }
                _trayMenu.ToggleNetFilter(_mainController.IsRunning);
                _logger.LogInformation("ToggleNetFilterAsync completed successfully. Service is now: {IsRunning}", _mainController.IsRunning ? "Running" : "Stopped");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to toggle OmniPoss service: {Exception}", ex);
                _logger.LogError(ex, "Exception details - Type: {Type}, Message: {Message}, StackTrace: {StackTrace}",
                    ex.GetType().Name, ex.Message, ex.StackTrace);
                // Don't rethrow - log the error but don't crash the app
                // The user can try again via the tray menu
                // Update tray menu to reflect actual state
                try
                {
                    _trayMenu.ToggleNetFilter(_mainController.IsRunning);
                }
                catch (Exception menuEx)
                {
                    _logger.LogError(menuEx, "Failed to update tray menu after error");
                }
            }
        }

        private void ToggleProxy()
        {
            try
            {
                bool wasEnabled = _proxyService.IsEnabled;
                _logger.LogInformation("Toggling proxy: Current state = {CurrentState}", wasEnabled ? "Enabled" : "Disabled");

                if (wasEnabled)
                {
                    _logger.LogInformation("Disabling proxy via tray menu...");
                    _proxyService.Disable();
                    _logger.LogInformation("Proxy disabled successfully via tray menu");
                }
                else
                {
                    _logger.LogInformation("Enabling proxy via tray menu: {Hostname}:{Port}...",
                        _config.ProxyConfig.Hostname, _config.ProxyConfig.Port);
                    _proxyService.Enable(_config.ProxyConfig);
                    _logger.LogInformation("Proxy enabled successfully via tray menu");
                }
                _trayMenu.ToggleProxy(_proxyService.IsEnabled);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to toggle proxy");
                throw;
            }
        }

        private void ToggleConsole()
        {
            try
            {
                if (!OmniPoss.Interop.ConsoleManager.IsEnabled)
                {
                    OmniPoss.Interop.ConsoleManager.Show();
                }
                else
                {
                    OmniPoss.Interop.ConsoleManager.Hide();
                }
                _trayMenu.ToggleConsole(OmniPoss.Interop.ConsoleManager.IsEnabled);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to toggle console");
            }
        }

        private void OpenConfigFolder()
        {
            var dataPath = Path.GetFullPath(Path.Combine("data"));
            System.Diagnostics.Process.Start("explorer.exe", dataPath);
        }

        private void OpenCoresFolder()
        {
            var coresPath = Path.GetFullPath(Path.Combine("data", "cores"));
            System.Diagnostics.Process.Start("explorer.exe", coresPath);
        }

        /// <summary>
        /// Performs a true hot-reload: reloads configuration from disk and applies changes to running services.
        /// 
        /// Flow:
        /// 1. Reads ACTUAL current state (what's actually running right now)
        /// 2. Reloads configuration from disk
        /// 3. Updates in-memory configuration
        /// 4. Relaunches services ONLY if they are currently running AND config changed:
        ///    - Cores: Relaunch ALL currently running cores (configs managed externally, can't detect changes)
        ///    - MainController: Restart if running AND config changed
        ///    - ProxyService: Update if enabled AND config changed
        /// 
        /// Note: This is a RELOAD, not a RESTART. Services that are not running will not be started.
        /// </summary>
        public async Task ReloadAsync()
        {
            try
            {
                _logger.LogInformation("Hot-reload requested - reloading configuration from disk...");

                // Step 1: Read ACTUAL current state (what's actually running right now)
                var runningCoreKeys = _coreManager.GetRunning().ToArray(); // Get actual running cores
                var isMainControllerRunning = _mainController.IsRunning; // Check actual state
                var isProxyEnabled = _proxyService.IsEnabled; // Check actual state

                _logger.LogInformation("Current state - Running cores: {CoreCount}, MainController: {MainControllerState}, Proxy: {ProxyState}",
                    runningCoreKeys.Length, isMainControllerRunning ? "Running" : "Stopped", isProxyEnabled ? "Enabled" : "Disabled");

                // Step 2: Reload configuration from disk
                ApplicationConfig newConfig;
                try
                {
                    if (!File.Exists(ConfigPath))
                    {
                        _logger.LogWarning("Configuration file not found at {ConfigPath}. Reload aborted.", ConfigPath);
                        return;
                    }

                    string json = await File.ReadAllTextAsync(ConfigPath);
                    newConfig = JsonConvert.DeserializeObject<ApplicationConfig>(json)
                        ?? throw new JsonReaderException("Failed to deserialize configuration.");

                    _logger.LogInformation("Configuration loaded successfully from {ConfigPath}", ConfigPath);
                }
                catch (JsonReaderException ex)
                {
                    _logger.LogError(ex, "Cannot parse config file. Reload aborted.");
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error loading configuration. Reload aborted.");
                    return;
                }

                // Step 3: Update in-memory configuration (update properties, not replace object)
                var oldConfig = CreateConfigSnapshot(_config);
                UpdateConfigProperties(_config, newConfig);

                // Step 4: Update CoreProcessManager's core list
                UpdateCoreManagerCores(newConfig.Cores);

                // Step 5: Relaunch all currently running cores (configs managed externally)
                await RelaunchRunningCoresAsync(runningCoreKeys, newConfig.Cores);

                // Step 6: Reload MainController if running and config changed
                await ReloadMainControllerIfRunningAsync(isMainControllerRunning, oldConfig, newConfig);

                // Step 7: Update ProxyConfig (always) and reload ProxyService if running and config changed
                ReloadProxyServiceIfEnabled(isProxyEnabled, oldConfig);

                // Step 8: Update Socks5ClientService properties
                await ApplySocks5ClientServiceChangesAsync(newConfig.Socks5ServerConfig);

                // Step 9: Update tray menu (initial state - will be updated as async operations complete)
                UpdateTrayMenu(newConfig);

                // Step 10: Update NetFilter and Proxy status immediately (they're synchronous or already updated)
                _trayMenu.ToggleNetFilter(_mainController.IsRunning);
                _trayMenu.ToggleProxy(_proxyService.IsEnabled);

                _logger.LogInformation("Hot-reload completed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reload configuration");
            }
        }

        /// <summary>
        /// Creates a snapshot of the current configuration for comparison.
        /// </summary>
        private ApplicationConfig CreateConfigSnapshot(ApplicationConfig config)
        {
            return new ApplicationConfig
            {
                AutoStart = config.AutoStart,
                Cores = config.Cores.Select(c => new CoreConfig(c.Key, c.ExePath, c.Argument) { Enabled = c.Enabled }).ToList(),
                Socks5ServerConfig = new Socks5ClientConfig { Hostname = config.Socks5ServerConfig.Hostname, Port = config.Socks5ServerConfig.Port },
                ProxyConfig = new ProxyConfig(config.ProxyConfig.Hostname, config.ProxyConfig.Port) { Enabled = config.ProxyConfig.Enabled },
                NFConfig = new NFConfig
                {
                    Enabled = config.NFConfig.Enabled,
                    FilterTCP = config.NFConfig.FilterTCP,
                    FilterUDP = config.NFConfig.FilterUDP,
                    FilterDNS = config.NFConfig.FilterDNS,
                    FilterICMP = config.NFConfig.FilterICMP,
                    FilterIntranet = config.NFConfig.FilterIntranet,
                    FilterLoopback = config.NFConfig.FilterLoopback,
                    FilterParent = config.NFConfig.FilterParent,
                    DNSHost = config.NFConfig.DNSHost,
                    DNSProxy = config.NFConfig.DNSProxy,
                    HandleOnlyDNS = config.NFConfig.HandleOnlyDNS,
                    ICMPDelay = config.NFConfig.ICMPDelay,
                    Bypass = config.NFConfig.Bypass?.ToList() ?? [],
                    Handle = config.NFConfig.Handle?.ToList() ?? []
                }
            };
        }

        /// <summary>
        /// Updates the properties of the existing config object with values from the new config.
        /// This preserves the object reference so services that hold references continue to work.
        /// </summary>
        private void UpdateConfigProperties(ApplicationConfig existing, ApplicationConfig newConfig)
        {
            // Update AutoStart
            existing.AutoStart = newConfig.AutoStart;

            // Update cores list
            existing.Cores.Clear();
            existing.Cores.AddRange(newConfig.Cores);

            // Update Socks5ServerConfig
            existing.Socks5ServerConfig.Hostname = newConfig.Socks5ServerConfig.Hostname;
            existing.Socks5ServerConfig.Port = newConfig.Socks5ServerConfig.Port;

            // Update ProxyConfig (create new instance since it's a struct with init-only properties)
            existing.ProxyConfig = new ProxyConfig(newConfig.ProxyConfig.Hostname, newConfig.ProxyConfig.Port)
            {
                Enabled = newConfig.ProxyConfig.Enabled
            };

            // Update NFConfig
            var nf = existing.NFConfig;
            var newNf = newConfig.NFConfig;
            nf.Enabled = newNf.Enabled;
            nf.FilterTCP = newNf.FilterTCP;
            nf.FilterUDP = newNf.FilterUDP;
            nf.FilterDNS = newNf.FilterDNS;
            nf.FilterICMP = newNf.FilterICMP;
            nf.FilterIntranet = newNf.FilterIntranet;
            nf.FilterLoopback = newNf.FilterLoopback;
            nf.FilterParent = newNf.FilterParent;
            nf.DNSHost = newNf.DNSHost;
            nf.DNSProxy = newNf.DNSProxy;
            nf.HandleOnlyDNS = newNf.HandleOnlyDNS;
            nf.ICMPDelay = newNf.ICMPDelay;
            nf.Bypass = newNf.Bypass ?? [];
            nf.Handle = newNf.Handle ?? [];
        }

        /// <summary>
        /// Updates the CoreProcessManager's internal core dictionary with new cores.
        /// </summary>
        private void UpdateCoreManagerCores(List<CoreConfig> newCores)
        {
            // Update the service provider's core list
            var coresList = _serviceProvider.GetRequiredService<List<CoreConfig>>();
            coresList.Clear();
            coresList.AddRange(newCores);
        }

        /// <summary>
        /// Relaunches all currently running cores.
        /// Since core configs are managed externally (e.g., sing-box config files), we can't detect changes.
        /// Therefore, we restart all running cores to pick up any external config changes.
        /// </summary>
        private Task RelaunchRunningCoresAsync(string[] runningCoreKeys, List<CoreConfig> newCores)
        {
            var cancellationToken = _shutdownCts.Token;

            foreach (var runningKey in runningCoreKeys)
            {
                // Find the core config for this running core
                var core = newCores.FirstOrDefault(c => c.Key == runningKey);
                if (core == null)
                {
                    _logger.LogWarning("[{CoreKey}] Core config not found in new config, skipping reload", runningKey);
                    continue;
                }

                _logger.LogInformation("[{CoreKey}] Relaunching core to pick up external config changes", runningKey);

                // Kill the existing process
                _coreManager.Kill(runningKey);

                // Relaunch the core
                var task = Task.Run(async () =>
                {
                    try
                    {
                        await _coreManager.LaunchAsync(core);
                        _logger.LogInformation("[{CoreKey}] Core relaunched successfully", runningKey);
                        // Update menu status after relaunch completes
                        _trayMenu.ToggleCore(runningKey, _coreManager.IsRunning(runningKey));
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogInformation("[{CoreKey}] Core relaunch cancelled", runningKey);
                        // Update menu status even if cancelled
                        _trayMenu.ToggleCore(runningKey, _coreManager.IsRunning(runningKey));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[{CoreKey}] Failed to relaunch core", runningKey);
                        // Update menu status even if failed
                        _trayMenu.ToggleCore(runningKey, _coreManager.IsRunning(runningKey));
                    }
                }, cancellationToken);
                _backgroundTasks.Add(task);
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Reloads MainController if it's currently running and config changed.
        /// Does NOT start MainController if it's not running (this is a reload, not a restart).
        /// </summary>
        private async Task ReloadMainControllerIfRunningAsync(bool isRunning, ApplicationConfig oldConfig, ApplicationConfig newConfig)
        {
            if (!isRunning)
            {
                _logger.LogInformation("MainController is not running, skipping reload");
                return;
            }

            // Check if any relevant config changed
            bool configChanged = false;

            // Check SOCKS5 config
            if (oldConfig.Socks5ServerConfig.Hostname != newConfig.Socks5ServerConfig.Hostname ||
                oldConfig.Socks5ServerConfig.Port != newConfig.Socks5ServerConfig.Port)
            {
                _logger.LogInformation("SOCKS5 config changed: {OldHost}:{OldPort} -> {NewHost}:{NewPort}",
                    oldConfig.Socks5ServerConfig.Hostname, oldConfig.Socks5ServerConfig.Port,
                    newConfig.Socks5ServerConfig.Hostname, newConfig.Socks5ServerConfig.Port);
                configChanged = true;
            }

            // Check NFConfig changes
            var oldNf = oldConfig.NFConfig;
            var newNf = newConfig.NFConfig;
            if (oldNf.FilterTCP != newNf.FilterTCP ||
                oldNf.FilterUDP != newNf.FilterUDP ||
                oldNf.FilterDNS != newNf.FilterDNS ||
                oldNf.FilterICMP != newNf.FilterICMP ||
                oldNf.FilterIntranet != newNf.FilterIntranet ||
                oldNf.FilterLoopback != newNf.FilterLoopback ||
                oldNf.FilterParent != newNf.FilterParent ||
                oldNf.DNSHost != newNf.DNSHost ||
                oldNf.DNSProxy != newNf.DNSProxy ||
                oldNf.HandleOnlyDNS != newNf.HandleOnlyDNS ||
                oldNf.ICMPDelay != newNf.ICMPDelay ||
                !(oldNf.Bypass ?? []).SequenceEqual(newNf.Bypass ?? []) ||
                !(oldNf.Handle ?? []).SequenceEqual(newNf.Handle ?? []))
            {
                _logger.LogInformation("NFConfig changed");
                configChanged = true;
            }

            if (configChanged)
            {
                _logger.LogInformation("Reloading MainController (config changed)");
                await _mainController.StopAsync();
                var task = Task.Run(async () =>
                {
                    try
                    {
                        await _mainController.StartAsync();
                        _trayMenu.ToggleNetFilter(_mainController.IsRunning);
                        _logger.LogInformation("MainController reloaded successfully");
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogInformation("MainController reload cancelled");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to reload MainController");
                    }
                }, _shutdownCts.Token);
                _backgroundTasks.Add(task);
            }
            else
            {
                _logger.LogInformation("MainController config unchanged, no reload needed");
            }
        }

        /// <summary>
        /// Updates ProxyConfig (always) and reloads ProxyService if it's currently enabled and config changed.
        /// Note: ProxyConfig is stored in ApplicationConfig and is always updated during reload.
        /// The service is only relaunched if it's actually running at the moment.
        /// Uses _config.ProxyConfig (the updated in-memory config) to set the proxy.
        /// </summary>
        private void ReloadProxyServiceIfEnabled(bool isEnabled, ApplicationConfig oldConfig)
        {
            _logger.LogDebug("ReloadProxyServiceIfEnabled: Service enabled = {IsEnabled}", isEnabled);
            var oldProxy = oldConfig.ProxyConfig;
            // Use _config.ProxyConfig (already updated by UpdateConfigProperties) as the source of truth
            var currentProxy = _config.ProxyConfig;

            // Check if proxy config changed
            bool configChanged = oldProxy.Hostname != currentProxy.Hostname || oldProxy.Port != currentProxy.Port || oldProxy.Enabled != currentProxy.Enabled;

            if (configChanged)
            {
                _logger.LogInformation("ProxyConfig updated: {OldHost}:{OldPort} (Enabled: {OldEnabled}) -> {NewHost}:{NewPort} (Enabled: {NewEnabled})",
                    oldProxy.Hostname, oldProxy.Port, oldProxy.Enabled, currentProxy.Hostname, currentProxy.Port, currentProxy.Enabled);
            }

            // Relaunch service ONLY if it's currently enabled/running
            if (isEnabled)
            {
                if (configChanged)
                {
                    _logger.LogInformation("Reloading ProxyService (service is running and config changed)");
                    try
                    {
                        _proxyService.Disable();
                        _logger.LogDebug("ProxyService disabled for reload");
                        // Use _config.ProxyConfig to ensure we're using the updated in-memory config
                        _proxyService.Enable(_config.ProxyConfig);
                        _logger.LogInformation("ProxyService reloaded successfully with {Host}:{Port}", currentProxy.Hostname, currentProxy.Port);
                        // Update menu status after reload
                        _trayMenu.ToggleProxy(_proxyService.IsEnabled);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to reload ProxyService during hot-reload");
                        throw;
                    }
                }
                else
                {
                    _logger.LogInformation("ProxyService is running but config unchanged, no reload needed");
                }
            }
            else
            {
                if (configChanged)
                {
                    _logger.LogInformation("ProxyConfig updated but service is not running, config will be applied when service is enabled");
                }
                else
                {
                    _logger.LogDebug("ProxyConfig unchanged and service is not running");
                }
            }
        }

        /// <summary>
        /// Applies changes to Socks5ClientService: updates properties if config changed.
        /// Note: If MainController is running and SOCKS5 config changed, it will be restarted by ApplyMainControllerChangesAsync.
        /// </summary>
        private Task ApplySocks5ClientServiceChangesAsync(Socks5ClientConfig newConfig)
        {
            var socks5Service = _serviceProvider.GetRequiredService<Socks5ClientService>();

            if (socks5Service.Hostname != newConfig.Hostname)
            {
                _logger.LogInformation("Updating SOCKS5 hostname: {Old} -> {New}", socks5Service.Hostname, newConfig.Hostname);
                socks5Service.Hostname = newConfig.Hostname;
            }

            if (socks5Service.Port != newConfig.Port)
            {
                _logger.LogInformation("Updating SOCKS5 port: {Old} -> {New}", socks5Service.Port, newConfig.Port);
                socks5Service.Port = newConfig.Port;
            }

            // If MainController is running and SOCKS5 config changed, it will be restarted by ApplyMainControllerChangesAsync
            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates the tray menu to reflect the new configuration state.
        /// </summary>
        private void UpdateTrayMenu(ApplicationConfig newConfig)
        {
            // Update core status (running state for colored circle indicator)
            foreach (var core in newConfig.Cores)
            {
                _trayMenu.ToggleCore(core.Key, _coreManager.IsRunning(core.Key));
            }

            // Update StartWithWindows menu item
            _trayMenu.ToggleStartWithWindows(newConfig.AutoStart);

            // Update OmniPoss and Proxy states are handled in their respective apply methods
        }

        /// <summary>
        /// Exits the application by cleaning up and exiting the message loop.
        /// Can be called from user action or Windows shutdown signal.
        /// </summary>
        public async Task ExitApplicationAsync()
        {
            try
            {
                // Determine if this is a Windows shutdown or user-initiated exit
                var isWindowsShutdown = Environment.HasShutdownStarted;
                _logger.LogInformation("Exit requested ({Source})", isWindowsShutdown ? "Windows shutdown" : "user");

                // Perform cleanup (stop services, kill processes, dispose tray icon)
                await CleanUpAsync();

                // During Windows shutdown, the form will close itself after cleanup
                // Don't call Application.Exit() here as it may cause deadlock during shutdown
                // The ShutdownHandlerForm will close the form on the UI thread after cleanup completes
                if (!isWindowsShutdown)
                {
                    // Only exit application for user-initiated shutdowns
                    // Exit the Windows Forms message loop
                    // This will cause Application.Run() to return
                    // Must be called on the UI thread
                    if (System.Windows.Forms.Application.MessageLoop)
                    {
                        // Check if we need to marshal to UI thread
                        if (System.Windows.Forms.Application.OpenForms.Count > 0)
                        {
                            var form = System.Windows.Forms.Application.OpenForms[0];
                            if (form != null && form.InvokeRequired)
                            {
                                form.Invoke(new Action(() => System.Windows.Forms.Application.Exit()));
                            }
                            else
                            {
                                System.Windows.Forms.Application.Exit();
                            }
                        }
                        else
                        {
                            // No forms but message loop exists - safe to call directly
                            System.Windows.Forms.Application.Exit();
                        }
                    }
                    else
                    {
                        // No message loop, process is likely terminating
                        _logger.LogWarning("Application message loop not available, process may be terminating");
                    }
                }
                else
                {
                    // During Windows shutdown, just log - form will handle closing
                    _logger.LogInformation("Cleanup complete during Windows shutdown - form will close automatically");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during exit");
                // Force exit even if cleanup fails
                System.Windows.Forms.Application.Exit();
            }
        }

        /// <summary>
        /// Cleans up all resources and stops all services.
        /// </summary>
        public async Task CleanUpAsync()
        {
            try
            {
                _logger.LogInformation("Starting cleanup...");

                // Cancel all background tasks
                _logger.LogInformation("Cancelling background tasks...");
                await _shutdownCts.CancelAsync();

                // Wait for background tasks to complete (with timeout)
                // Log any exceptions from background tasks
                try
                {
                    var tasks = _backgroundTasks.ToArray();
                    if (tasks.Length > 0)
                    {
                        _logger.LogInformation("Waiting for {Count} background tasks to complete...", tasks.Length);
                        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5));
                        _logger.LogInformation("All background tasks completed");
                    }
                }
                catch (TimeoutException)
                {
                    _logger.LogWarning("Some background tasks did not complete within timeout");
                    // Log which tasks are still running
                    foreach (var task in _backgroundTasks)
                    {
                        if (!task.IsCompleted)
                        {
                            _logger.LogWarning("Background task still running: Status={Status}, Exception={Exception}",
                                task.Status, task.Exception?.ToString() ?? "None");
                        }
                        else if (task.IsFaulted)
                        {
                            _logger.LogError(task.Exception, "Background task faulted: {Exception}", task.Exception);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error waiting for background tasks");
                    // Log any exceptions from background tasks
                    foreach (var task in _backgroundTasks)
                    {
                        if (task.IsFaulted && task.Exception != null)
                        {
                            _logger.LogError(task.Exception, "Background task exception: {Exception}", task.Exception);
                        }
                    }
                }

                if (_mainController.IsRunning)
                {
                    _logger.LogInformation("Stopping MainController (OmniPoss service) during cleanup...");
                    try
                    {
                        await _mainController.StopAsync();
                        _logger.LogInformation("MainController (OmniPoss service) stopped successfully during cleanup");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to stop MainController during cleanup");
                        // Continue with cleanup even if MainController stop fails
                    }
                }
                else
                {
                    _logger.LogDebug("MainController (OmniPoss service) is already stopped, skipping cleanup");
                }

                if (_proxyService.IsEnabled)
                {
                    _logger.LogInformation("Disabling proxy during cleanup...");
                    try
                    {
                        _proxyService.Disable();
                        _logger.LogInformation("Proxy disabled successfully during cleanup");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to disable proxy during cleanup");
                        // Continue with cleanup even if proxy disable fails
                    }
                }
                else
                {
                    _logger.LogDebug("Proxy is already disabled, skipping proxy cleanup");
                }

                _logger.LogInformation("Killing all core processes...");
                _coreManager.KillAll();

                OmniPoss.Interop.ConsoleManager.Close();

                _trayIcon?.Dispose();
                _trayIcon = null;

                _logger.LogInformation("Cleanup completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during cleanup");
            }
        }

        /// <summary>
        /// Toggles the AutoStart setting, saves the configuration, and updates the startup shortcut.
        /// </summary>
        private async Task ToggleStartupAsync()
        {
            try
            {
                bool wasEnabled = _config.AutoStart;
                _config.AutoStart = !wasEnabled;

                _logger.LogInformation("Toggling AutoStart: {OldState} -> {NewState}", wasEnabled ? "Enabled" : "Disabled", _config.AutoStart ? "Enabled" : "Disabled");

                // Save configuration to file
                await SaveConfigAsync();

                // Update startup shortcut
                OmniPoss.Program.ManageStartupShortcut(_config.AutoStart);

                // Update tray menu
                _trayMenu.ToggleStartWithWindows(_config.AutoStart);

                _logger.LogInformation("AutoStart toggled successfully to {State}", _config.AutoStart ? "Enabled" : "Disabled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to toggle AutoStart");
                // Revert the change on error
                _config.AutoStart = !_config.AutoStart;
            }
        }

        /// <summary>
        /// Saves the current configuration to the config file.
        /// </summary>
        private async Task SaveConfigAsync()
        {
            try
            {
                string json = JsonConvert.SerializeObject(_config, Formatting.Indented);
                await File.WriteAllTextAsync(ConfigPath, json);
                _logger.LogInformation("Configuration saved successfully to {ConfigPath}", ConfigPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save configuration to {ConfigPath}", ConfigPath);
                throw;
            }
        }

        public void Dispose()
        {
            _trayIcon?.Dispose();
            _coreManager?.Dispose();
            _shutdownCts?.Dispose();
        }
    }
}
