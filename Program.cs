using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OmniPoss.Configuration;
using OmniPoss.Core;
using OmniPoss.Infrastructure;
using OmniPoss.Interop;
using Newtonsoft.Json;
using Serilog;
using System.Diagnostics;
using System.Runtime.InteropServices;
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

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        [STAThread]
        static async Task Main(string[] args)
        {
            // Set up global exception handlers for Windows Forms
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (sender, e) =>
            {
                try
                {
                    Log.Fatal(e.Exception, "Unhandled Windows Forms thread exception");
                }
                catch
                {
                    try
                    {
                        MessageBox.Show($"Unhandled exception: {e.Exception}", "OmniPoss Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    catch
                    {
                        // If even MessageBox fails, we're in deep trouble
                    }
                }
            };

            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                try
                {
                    if (e.ExceptionObject is Exception ex)
                    {
                        Log.Fatal(ex, "Unhandled AppDomain exception (IsTerminating: {IsTerminating})", e.IsTerminating);
                    }
                    else
                    {
                        Log.Fatal("Unhandled AppDomain exception (IsTerminating: {IsTerminating}): {ExceptionObject}", e.IsTerminating, e.ExceptionObject);
                    }
                }
                catch
                {
                    try
                    {
                        if (e.ExceptionObject is Exception ex)
                        {
                            MessageBox.Show($"Unhandled exception: {ex}", "OmniPoss Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    catch
                    {
                        // If even MessageBox fails, we're in deep trouble
                    }
                }
            };

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
            try
            {
                OmniPoss.Infrastructure.Interop.NativeMethods.SetProcessShutdownParameters(0x3FF, 0);
            }
            catch
            {
                // Failed to set shutdown parameters - non-critical
            }

            // Initialize console before logging (so we can see logs)
            ConsoleManager.InitConsole();

            // Configure Serilog with console and file sinks
            Log.Logger = new LoggerConfiguration()
#if DEBUG
                .MinimumLevel.Debug()
#else
                .MinimumLevel.Information()
#endif
                .WriteTo.Console(
                    outputTemplate: "[{Timestamp:HH:mm:ss.fff}] [{Level:u3}] {Message:lj}{NewLine}{Exception}")
                .WriteTo.File(
                    logPath,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 7,
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();

            Log.Information("OmniPoss starting...");

            try
            {
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

                // Set DLL directory for native DLL loading (must be done before any P/Invoke)
                if (Directory.Exists(binPath))
                {
                    SetDllDirectory(binPath);
                }

                // Load configuration
                var config = await LoadConfigAsync();

#if !DEBUG
                // Manage startup shortcut based on AutoStart flag (Release builds only)
                ManageStartupShortcut(config.AutoStart);
#endif

                // Setup dependency injection
                var services = new ServiceCollection();
                services.AddNetFilterServices(config);
                using var serviceProvider = services.BuildServiceProvider();

                using var appHost = new ApplicationHost(serviceProvider);
                await appHost.InitializeAsync();

                ConsoleManager.Hide();

                // Setup Windows Forms
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

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
                    // This blocks until the form is closed or Application.Exit() is called
                    Application.Run(shutdownForm);
                }
                catch (OperationCanceledException)
                {

                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "Fatal error occurred in message loop");
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
        /// Creates or removes a shortcut in the Windows Startup folder based on the AutoStart flag.
        /// </summary>
        /// <param name="autoStart">If true, creates the shortcut; if false, removes it.</param>
        private static void ManageStartupShortcut(bool autoStart)
        {
            try
            {
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string shortcutPath = Path.Combine(startup, "OmniPoss.lnk");

                if (autoStart)
                {
                    // Create startup shortcut
                    string targetPath = Environment.ProcessPath!;
                    string workingDirectory = Path.GetDirectoryName(targetPath)!;

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
                            Log.Information("Startup shortcut created successfully.");
                        }
                    }
                }
                else
                {
                    // Remove startup shortcut if it exists
                    if (File.Exists(shortcutPath))
                    {
                        File.Delete(shortcutPath);
                        Log.Information("Startup shortcut removed successfully.");
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to manage startup shortcut - non-critical");
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
                    Verb = "runas",
                    WorkingDirectory = Environment.CurrentDirectory
                };

                Process.Start(startInfo);
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
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
