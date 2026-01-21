using OmniPoss.Utilities;
using OmniPoss.Interop;
using Microsoft.Extensions.Logging;
using System.ServiceProcess;

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
            NFDriver = Path.Combine("bin", "nfdriver.sys");
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
                return;
            }

            _logger.LogInformation("Uninstalling existing driver...");
            UninstallDriver();
            _logger.LogInformation("Installing new driver...");
            InstallDriver();
            _logger.LogInformation("Driver updated successfully");
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
                _logger.LogDebug("Unregistering redirector...");
                Redirector.aio_unregister("netfilter2");
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
