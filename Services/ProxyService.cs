using OmniPoss.Configuration;
using Microsoft.Win32;
using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;

namespace OmniPoss.Services
{
    internal class ProxyService(ILogger<ProxyService> logger)
    {
        private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        private const int INTERNET_OPTION_REFRESH = 37;

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        private readonly ILogger<ProxyService> _logger = logger;

        public bool IsEnabled { get; private set; } = false;

        /// <summary>
        /// Checks the registry to determine if the proxy is currently enabled.
        /// </summary>
        public bool CheckRegistryState()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
                if (key == null)
                {
                    _logger.LogWarning("Failed to open Internet Settings registry key for state check");
                    return false;
                }

                var proxyEnable = key.GetValue("ProxyEnable");
                if (proxyEnable is int value)
                {
                    bool isEnabled = value != 0;
                    _logger.LogDebug("Registry proxy state check: {State}", isEnabled ? "Enabled" : "Disabled");
                    return isEnabled;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking registry proxy state, assuming disabled");
            }
            return false;
        }

        public void Enable(ProxyConfig proxyConfig)
        {
            _logger.LogInformation("Enabling proxy: {Hostname}:{Port}", proxyConfig.Hostname, proxyConfig.Port);

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key == null)
                    {
                        _logger.LogError("Failed to open Internet Settings registry key");
                        throw new InvalidOperationException("Failed to open Internet Settings registry key");
                    }

                    key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", $"{proxyConfig.Hostname}:{proxyConfig.Port}", RegistryValueKind.String);

                    // Set ProxyOverride to bypass local addresses
                    // <local> bypasses localhost, 127.0.0.1, and other local addresses
                    key.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
                    _logger.LogDebug("Proxy registry settings updated: ProxyEnable=1, ProxyServer={Hostname}:{Port}, ProxyOverride=<local>",
                        proxyConfig.Hostname, proxyConfig.Port);
                }

                IsEnabled = true;
                _logger.LogDebug("Proxy state set to enabled");

                ApplySettings();
                _logger.LogInformation("Proxy enabled successfully: {Hostname}:{Port}", proxyConfig.Hostname, proxyConfig.Port);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enable proxy: {Hostname}:{Port}", proxyConfig.Hostname, proxyConfig.Port);
                IsEnabled = false;
                throw;
            }
        }

        public void Disable()
        {
            _logger.LogInformation("Disabling proxy");

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
                {
                    if (key == null)
                    {
                        _logger.LogError("Failed to open Internet Settings registry key");
                        throw new InvalidOperationException("Failed to open Internet Settings registry key");
                    }

                    key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                    _logger.LogDebug("Proxy registry setting updated: ProxyEnable=0");
                }

                IsEnabled = false;
                _logger.LogDebug("Proxy state set to disabled");

                ApplySettings();
                _logger.LogInformation("Proxy disabled successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to disable proxy");
                // Don't throw here - we want to mark as disabled even if ApplySettings fails
                IsEnabled = false;
                throw;
            }
        }

        private void ApplySettings()
        {
            _logger.LogDebug("Applying proxy settings to system (notifying Internet Explorer settings change)");

            try
            {
                bool result1 = InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
                bool result2 = InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);

                if (!result1 || !result2)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    _logger.LogWarning("InternetSetOption returned false. Last error: {ErrorCode}", errorCode);
                }
                else
                {
                    _logger.LogDebug("Proxy settings applied successfully");
                }
            }
            catch (EntryPointNotFoundException ex)
            {
                _logger.LogError(ex, "InternetSetOption entry point not found in wininet.dll");
                throw new InvalidOperationException("Failed to apply proxy settings: InternetSetOption entry point not found. This may indicate a system configuration issue.", ex);
            }
            catch (DllNotFoundException ex)
            {
                _logger.LogError(ex, "wininet.dll not found");
                throw new InvalidOperationException("Failed to apply proxy settings: wininet.dll not found.", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error applying proxy settings");
                throw;
            }
        }
    }
}
