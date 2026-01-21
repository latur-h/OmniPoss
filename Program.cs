using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OmniPoss.Configuration;
using OmniPoss.Core;
using OmniPoss.Infrastructure;
using OmniPoss.Interop;
using Newtonsoft.Json;
using Serilog;
using System.Diagnostics;
using System.Security.Principal;
using File = System.IO.File;

namespace OmniPoss
{
    internal class Program
    {
        private static readonly string MutexName = "Global\\OmniPoss";
        private static readonly string DataPath = Path.GetFullPath(Path.Combine("data"));
        private static readonly string ConfigPath = Path.Combine(DataPath, "configs.json");
        private static readonly string CoresPath = Path.Combine(DataPath, "cores");

        [STAThread]
        static async Task Main()
        {
            // Check and request administrator privileges
            if (!IsRunningAsAdministrator())
            {
                RequestAdministratorRights();
                return;
            }

            // Ensure data directories exist first (needed for log path)
            Directory.CreateDirectory(DataPath);
            Directory.CreateDirectory(CoresPath);

            // Configure Serilog - create logs directory
            var logsDirectory = Path.Combine(DataPath, "logs");
            Directory.CreateDirectory(logsDirectory);
            var logPath = Path.Combine(logsDirectory, "omniposs-.log");

            // Set process shutdown parameters to ensure we receive shutdown messages early
            // Higher priority (0x3FF = highest) ensures we're processed before other apps
            // This helps Windows include us in the "Apps preventing shutdown" list
            try
            {
                OmniPoss.Infrastructure.Interop.NativeMethods.SetProcessShutdownParameters(0x3FF, 0);
                Log.Information("Process shutdown parameters set to highest priority");
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to set process shutdown parameters");
            }

            // Initialize console before logging (so we can see logs)
            ConsoleManager.InitConsole();

            // Configure Serilog with console and file sinks
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.Console(
                    outputTemplate: "[{Timestamp:HH:mm:ss.fff}] [{Level:u3}] {Message:lj}{NewLine}{Exception}")
                .WriteTo.File(
                    logPath,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 7,
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();

            // Test logging immediately
            Log.Information("Logging initialized. Log file: {LogPath}", logPath);

            try
            {
                Log.Information("OmniPoss starting...");

                // Single-instance enforcement
                using var mutex = new Mutex(true, MutexName, out bool isNewInstance);
                if (!isNewInstance)
                {
                    Log.Warning("Another instance is already running. Exiting.");
                    Environment.Exit(0);
                    return;
                }

                // Initialize native libraries
                var binPath = Path.Combine(Environment.CurrentDirectory, "bin");
                Environment.SetEnvironmentVariable("PATH", $"{Environment.GetEnvironmentVariable("PATH")};{binPath}");

#if !DEBUG
                // Create startup shortcut (Release builds only)
                CreateStartupShortcut();
#endif

                // Load configuration
                var config = await LoadConfigAsync();

                // Setup dependency injection
                var services = new ServiceCollection();
                services.AddOmniPossServices(config);
                using var serviceProvider = services.BuildServiceProvider();

                // Create application host
                using var appHost = new ApplicationHost(serviceProvider);

                // Initialize and start components
                await appHost.InitializeAsync();

                ConsoleManager.Hide();

                // Setup Windows Forms
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // Create tray icon
                var trayIcon = appHost.CreateTrayIcon();

                // Create hidden form to handle Windows shutdown signals
                var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
                var shutdownLogger = loggerFactory.CreateLogger<OmniPoss.UI.ShutdownHandlerForm>();
                var shutdownForm = new OmniPoss.UI.ShutdownHandlerForm(
                    async () => await appHost.ExitApplicationAsync(),
                    shutdownLogger);

                try
                {
                    // Run application message loop with shutdown handler form
                    Application.Run(shutdownForm);
                }
                catch (OperationCanceledException)
                {
                    Log.Information("Cancellation requested.");
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "Fatal error occurred");
                    throw;
                }
                finally
                {
                    // Final cleanup (tray icon already disposed by ExitApplicationAsync)
                    // This runs after Application.Run() returns
                    Log.Information("OmniPoss shutting down...");
                    await Log.CloseAndFlushAsync();
                }
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Unhandled exception in Main");
                throw;
            }
        }

        /// <summary>
        /// Creates a shortcut in the Windows Startup folder for auto-start.
        /// </summary>
        private static void CreateStartupShortcut()
        {
            try
            {
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string shortcutPath = Path.Combine(startup, "OmniPoss.lnk");
                string targetPath = Environment.ProcessPath!;
                string workingDirectory = Path.GetDirectoryName(targetPath)!;

                // Use COM object to create shortcut directly
                Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType != null)
                {
                    dynamic? shell = Activator.CreateInstance(shellType);
                    if (shell != null)
                    {
                        dynamic shortcut = shell.CreateShortcut(shortcutPath);
                        shortcut.TargetPath = targetPath;
                        shortcut.WorkingDirectory = workingDirectory;
                        shortcut.Save();
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to create startup shortcut");
            }
        }

        /// <summary>
        /// Loads application configuration from file or creates default configuration.
        /// </summary>
        private static async Task<ApplicationConfig> LoadConfigAsync()
        {
            ApplicationConfig config = new();

            try
            {
                if (File.Exists(ConfigPath))
                {
                    string json = await File.ReadAllTextAsync(ConfigPath);
                    config = JsonConvert.DeserializeObject<ApplicationConfig>(json)
                        ?? throw new JsonReaderException("Failed to deserialize configuration.");
                }
                else
                {
                    // Create default configuration file
                    string defaultJson = JsonConvert.SerializeObject(config, Formatting.Indented);
                    await File.WriteAllTextAsync(ConfigPath, defaultJson);
                }
            }
            catch (JsonReaderException ex)
            {
                Log.Error(ex, "Cannot parse config file. Using default configuration.");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error loading configuration. Using default configuration.");
            }

            return config;
        }

        /// <summary>
        /// Checks if the current process is running with administrator privileges.
        /// </summary>
        private static bool IsRunningAsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Restarts the application with administrator privileges using UAC elevation.
        /// </summary>
        private static void RequestAdministratorRights()
        {
            try
            {
                var exePath = Environment.ProcessPath;
                if (string.IsNullOrEmpty(exePath))
                {
                    MessageBox.Show(
                        "Unable to determine application path. Please run this application as administrator manually.",
                        "Administrator Rights Required",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    Environment.Exit(1);
                    return;
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true,
                    Verb = "runas", // This triggers UAC elevation
                    WorkingDirectory = Environment.CurrentDirectory
                };

                Process.Start(startInfo);
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                // User may have declined the UAC prompt
                MessageBox.Show(
                    $"Failed to request administrator rights: {ex.Message}\n\nPlease run this application as administrator manually.",
                    "Administrator Rights Required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
            }
        }
    }
}
