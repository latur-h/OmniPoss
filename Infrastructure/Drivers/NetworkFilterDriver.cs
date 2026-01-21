using OmniPoss.Utilities;
using Microsoft.Extensions.Logging;
using System.ServiceProcess;
using System.Diagnostics;

namespace OmniPoss.Infrastructure.Drivers
{
    internal class NetworkFilterDriver
    {
        private readonly ServiceController NFService = new("netfilter2");
        private readonly string NFDriver;
        private readonly string SystemDriver;
        private readonly ILogger<NetworkFilterDriver> _logger;

        public NetworkFilterDriver(ILogger<NetworkFilterDriver> logger)
        {
            _logger = logger;
            SystemDriver = Path.Combine(Environment.SystemDirectory, "drivers", "netfilter2.sys");
            // Look for driver in bin folder relative to current directory (where exe is located)
            NFDriver = Path.Combine(Environment.CurrentDirectory, "bin", "nfdriver.sys");
            _logger.LogDebug("NetworkFilterDriver initialized: NFDriver={NFDriver}, SystemDriver={SystemDriver}", NFDriver, SystemDriver);
        }

        /// <summary>
        /// Ensures the driver is installed and up-to-date. Checks version and installs/updates if needed.
        /// </summary>
        public void EnsureDriverInstalled()
        {
            _logger.LogInformation("Checking network filter driver installation...");

            if (!File.Exists(NFDriver))
            {
                _logger.LogError("Built-in driver file not found: {NFDriver}", NFDriver);
                throw new Exception("builtin driver files missing, can't install NF driver");
            }

            var binFileVersion = GeneralUtils.GetFileVersion(NFDriver);
            _logger.LogDebug("Built-in driver version: {Version}", binFileVersion ?? "Unknown");

            if (!File.Exists(SystemDriver))
            {
                _logger.LogInformation("System driver not found, installing driver...");
                InstallDriver();
                _logger.LogInformation("Driver installed successfully");
                return;
            }

            var systemFileVersion = GeneralUtils.GetFileVersion(SystemDriver);
            _logger.LogDebug("System driver version: {Version}", systemFileVersion ?? "Unknown");

            var reinstall = false;
            if (Version.TryParse(binFileVersion, out var binResult) && Version.TryParse(systemFileVersion, out var systemResult))
            {
                if (binResult.CompareTo(systemResult) > 0)
                {
                    _logger.LogInformation("Built-in driver ({BinVersion}) is newer than system driver ({SystemVersion}), updating...",
                        binResult, systemResult);
                    reinstall = true;
                }
                else if (systemResult.Major != binResult.Major)
                {
                    _logger.LogInformation("Major version mismatch (built-in: {BinMajor}, system: {SystemMajor}), reinstalling...",
                        binResult.Major, systemResult.Major);
                    reinstall = true;
                }
            }
            else
            {
                // Parse File versionName to Version failed
                if (!string.Equals(systemFileVersion, binFileVersion))
                {
                    _logger.LogInformation("Version strings differ (built-in: {BinVersion}, system: {SystemVersion}), reinstalling...",
                        binFileVersion, systemFileVersion);
                    reinstall = true;
                }
            }

            if (!reinstall)
            {
                _logger.LogDebug("Driver is up-to-date, no reinstall needed");
                // Even if not reinstalling, ensure the driver is registered with the API
                // This handles cases where the driver file exists but wasn't registered via nfregdrv.exe
                RegisterDriverWithAPI();
                return;
            }

            _logger.LogInformation("Uninstalling existing driver...");
            UninstallDriver();
            // Wait a moment for the service to fully stop
            System.Threading.Thread.Sleep(1000);
            _logger.LogInformation("Installing new driver...");
            InstallDriver();
            // Wait a moment for the service to fully start
            System.Threading.Thread.Sleep(1000);
            _logger.LogInformation("Driver updated successfully");
        }

        /// <summary>
        /// Registers the driver with the API using nfregdrv.exe
        /// </summary>
        private void RegisterDriverWithAPI()
        {
            try
            {
                var nfregdrvPath = Path.Combine(Environment.CurrentDirectory, "bin", "nfregdrv.exe");
                if (File.Exists(nfregdrvPath))
                {
                    _logger.LogDebug("Registering driver using nfregdrv.exe...");
                    var processStartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = nfregdrvPath,
                        Arguments = "netfilter2",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using var process = System.Diagnostics.Process.Start(processStartInfo);
                    if (process != null)
                    {
                        process.WaitForExit();
                        if (process.ExitCode == 0)
                        {
                            _logger.LogDebug("Driver registered successfully using nfregdrv.exe");
                        }
                        else
                        {
                            var error = process.StandardError.ReadToEnd();
                            _logger.LogDebug("nfregdrv.exe returned exit code {ExitCode} (may be OK if already registered): {Error}", process.ExitCode, error);
                        }
                    }
                }
                else
                {
                    _logger.LogDebug("nfregdrv.exe not found at {Path}, driver will be registered via API", nfregdrvPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to register driver via nfregdrv.exe, will try API registration instead");
            }
        }

        /// <summary>
        /// Installs the driver by copying it to the system drivers directory.
        /// </summary>
        private void InstallDriver()
        {
            if (!File.Exists(NFDriver))
            {
                _logger.LogError("Built-in driver file not found: {NFDriver}", NFDriver);
                throw new Exception("builtin driver files missing, can't install NF driver");
            }

            try
            {
                _logger.LogDebug("Copying driver from {Source} to {Destination}...", NFDriver, SystemDriver);
                File.Copy(NFDriver, SystemDriver, overwrite: true);
                _logger.LogInformation("Driver file copied successfully to {SystemDriver}", SystemDriver);

                // Register the driver using nfregdrv.exe (as per SDK install scripts)
                // This ensures the driver is properly registered with the API
                var nfregdrvPath = Path.Combine(Environment.CurrentDirectory, "bin", "nfregdrv.exe");
                if (File.Exists(nfregdrvPath))
                {
                    _logger.LogDebug("Registering driver using nfregdrv.exe...");
                    var processStartInfo = new ProcessStartInfo
                    {
                        FileName = nfregdrvPath,
                        Arguments = "netfilter2",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using var process = System.Diagnostics.Process.Start(processStartInfo);
                    if (process != null)
                    {
                        process.WaitForExit();
                        if (process.ExitCode == 0)
                        {
                            _logger.LogInformation("Driver registered successfully using nfregdrv.exe");
                        }
                        else
                        {
                            var error = process.StandardError.ReadToEnd();
                            _logger.LogWarning("nfregdrv.exe returned exit code {ExitCode}: {Error}", process.ExitCode, error);
                            // Continue anyway - driver might already be registered
                        }
                    }
                }
                else
                {
                    _logger.LogDebug("nfregdrv.exe not found at {Path}, driver will be registered via API", nfregdrvPath);
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Failed to copy driver file from {Source} to {Destination}", NFDriver, SystemDriver);
                throw new Exception($"Copy netfilter2.sys failed\n{e.Message}");
            }
        }

        /// <summary>
        /// Uninstalls the driver by stopping the service and removing the driver file.
        /// </summary>
        public bool UninstallDriver()
        {
            _logger.LogDebug("Uninstalling network filter driver...");

            try
            {
                if (NFService.Status == ServiceControllerStatus.Running)
                {
                    _logger.LogInformation("Stopping netfilter2 service...");
                    NFService.Stop();
                    NFService.WaitForStatus(ServiceControllerStatus.Stopped);
                    _logger.LogInformation("netfilter2 service stopped");
                }
                else
                {
                    _logger.LogDebug("netfilter2 service is not running (Status: {Status})", NFService.Status);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error stopping netfilter2 service, continuing with uninstall");
            }

            if (!File.Exists(SystemDriver))
            {
                _logger.LogDebug("System driver file does not exist, uninstall complete");
                return true;
            }

            try
            {
                _logger.LogDebug("Unregistering driver...");
                // Use native API to unregister driver (optional - may not be available in all SDK versions)
                try
                {
                    var status = Infrastructure.Interop.NativeNetFilterApi.nf_unRegisterDriver("netfilter2");
                    if (status != Infrastructure.Interop.NativeNetFilterApi.NF_STATUS.NF_STATUS_SUCCESS)
                    {
                        _logger.LogWarning("Failed to unregister driver via API (status: {Status}), continuing with file deletion", status);
                    }
                    else
                    {
                        _logger.LogDebug("Driver unregistered successfully via API");
                    }
                }
                catch (EntryPointNotFoundException)
                {
                    _logger.LogWarning("nf_unRegisterDriver not available in this SDK version, skipping API unregister");
                }
                catch (DllNotFoundException)
                {
                    _logger.LogWarning("nfapi.dll not found, skipping API unregister");
                }

                _logger.LogDebug("Deleting driver file: {SystemDriver}", SystemDriver);
                File.Delete(SystemDriver);
                _logger.LogInformation("Driver uninstalled successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during driver file removal");
                throw;
            }

            return true;
        }
    }
}
