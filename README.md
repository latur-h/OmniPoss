# OmniPoss

A **headless proxy client** for Windows that provides system-level network traffic interception and routing through any external proxy core (sing-box, xray, v2ray, etc.). OmniPoss acts as a flexible, protocol-agnostic proxy management layer that supports any protocol your chosen core supports.

## 🎯 Key Features

- **Protocol Agnostic**: Supports any protocol that your core supports (TUIC, VMess, VLESS, Shadowsocks, WireGuard, etc.)
- **Core Flexibility**: Launch and manage any proxy core executable via configuration
- **System-Level Interception**: Kernel-mode driver captures all network traffic before applications see it
- **SOCKS5 Bridge Architecture**: OmniPoss only speaks SOCKS5, cores handle everything else
- **Hot-Reload**: Reload configuration without restarting the application
- **Independent Core Management**: Start/stop cores individually via system tray menu
- **System Proxy Configuration**: Optional Windows system-wide proxy settings
- **Automatic Firewall Management**: Automatically manages Windows Firewall rules

## 🏗️ Architecture

OmniPoss follows a **"SOCKS5-only frontend, core-agnostic backend"** pattern:

1. **OmniPoss Layer (SOCKS5 Only)**:
   - Intercepts and redirects TCP/UDP/DNS traffic at the kernel level using a Windows driver (`netfilter2.sys`)
   - Runs local proxy servers (TCP on configurable port, default 8888; UDP via SOCKS5 UDP ASSOCIATE) that the kernel driver routes traffic to
   - Acts as a SOCKS5 client connecting to cores' SOCKS5 servers
   - Manages the kernel driver, firewall rules, and system proxy settings

2. **Core Layer (Any Protocol)**:
   - External executable processes (sing-box, xray, v2ray, or any proxy core)
   - Each core runs independently with its own configuration
   - Cores listen on local ports and handle their specific protocols (TUIC, VMess, VLESS, Shadowsocks, WireGuard, etc.)
   - Cores expose SOCKS5 servers that OmniPoss connects to

3. **Traffic Flow**:
   ```
   Application → Kernel Driver → Local Proxy (port 8888) → OmniPoss SOCKS5 Client → Core SOCKS5 Server → Core Protocol Handler → Upstream Server
   ```

**Key Innovation**: OmniPoss was originally created to support the **TUIC protocol**, which was unsupported by all proxy clients (including sing-box clients) at the time. By decoupling traffic interception from protocol handling, OmniPoss enables users to use any protocol their core supports, making it future-proof and highly flexible.

## 📋 Requirements

- **OS**: Windows 10.0.17763.0 or later
- **Architecture**: x64 or ARM64
- **Privileges**: Administrator (required for driver installation and network interception)
- **.NET**: 9.0 runtime

## 🔧 Technology Stack

- **Framework**: .NET 9.0 (Windows-specific: `net9.0-windows10.0.17763.0`)
- **UI**: Windows Forms (for system tray)
- **Configuration**: JSON (using Newtonsoft.Json)
- **Dependency Injection**: Microsoft.Extensions.DependencyInjection
- **Logging**: Serilog (console + file sinks, rolling daily, 7-day retention)
- **Native Interop**: P/Invoke for Windows APIs and NetFilterSDK
- **Key Libraries**:
  - `Socks5` (v1.0.2) - SOCKS5 protocol support
  - `Stun.Net` (v9.0.0) - NAT type testing
  - `WindowsFirewallHelper` (v2.2.0.86) - Firewall rule management
  - `Microsoft.Windows.CsWin32` - Windows API bindings
  - `Serilog` (v4.1.0) - Structured logging

## 🚀 Quick Start

1. **Download and Extract**: Extract OmniPoss to a directory (e.g., `C:\OmniPoss`)

2. **Run as Administrator**: Right-click `OmniPoss.exe` and select "Run as administrator"
   - The application will automatically request elevation if needed

3. **Configure Your Core**: 
   - Place your core executable (e.g., `sing-box.exe`) in `data/cores/`
   - Create your core's configuration file (e.g., `data/cores/sing-box.json`)
   - Edit `data/configs.json` to add your core configuration

4. **Configure OmniPoss**:
   - Edit `data/configs.json` to set the SOCKS5 endpoint that matches your core's SOCKS5 server address
   - Configure network filter settings as needed

5. **Start Using**: The application runs in the system tray. Right-click the tray icon to:
   - Start/stop OmniPoss service
   - Enable/disable system proxy
   - Start/stop individual cores
   - Reload configuration
   - View console output

## ⚙️ Configuration

### Configuration File: `data/configs.json`

```json
{
  "AutoStart": true,
  "Cores": [
    {
      "Key": "sing-box",
      "ExePath": "data/cores/sing-box.exe",
      "Argument": "-c data/cores/sing-box.json",
      "Enabled": true
    }
  ],
  "Socks5ServerConfig": {
    "Hostname": "127.0.0.1",
    "Port": 1080
  },
  "ProxyConfig": {
    "Enabled": false,
    "Hostname": "127.0.0.1",
    "Port": 1080
  },
  "NFConfig": {
    "Enabled": true,
    "FilterTCP": true,
    "FilterUDP": true,
    "FilterDNS": true,
    "FilterICMP": false,
    "FilterIntranet": true,
    "FilterLoopback": false,
    "FilterParent": true,
    "DNSHost": "1.1.1.1:53",
    "DNSProxy": true,
    "HandleOnlyDNS": true,
    "ICMPDelay": 10,
    "LocalProxyPort": 8888,
    "Bypass": [],
    "Handle": []
  }
}
```

### Configuration Sections

#### Cores
Define external proxy core executables to launch:
- `Key`: Unique identifier for the core
- `ExePath`: Path to the core executable (relative to application directory)
- `Argument`: Command-line arguments (typically includes path to core's config file)
- `Enabled`: Whether to auto-start on application launch

#### Socks5ServerConfig
Points to the SOCKS5 endpoint that your core exposes:
- `Hostname`: Core's SOCKS5 server address (typically `127.0.0.1`)
- `Port`: Core's SOCKS5 server port (typically `1080`)

**Important**: This must match the SOCKS5 server address configured in your core's own config file.

#### ProxyConfig
Optional Windows system-wide proxy settings:
- `Enabled`: Whether to configure Windows system proxy
- `Hostname`: Proxy server address
- `Port`: Proxy server port

#### NFConfig
Network filter configuration:
- `Enabled`: Whether to enable network filtering
- `FilterTCP`, `FilterUDP`, `FilterDNS`, `FilterICMP`: Protocol filtering (nullable - uses defaults from RedirectorConfig if not specified)
- `FilterLoopback`, `FilterIntranet`, `FilterParent`: Network scope filtering
- `DNSHost`: DNS server address (format: `ip:port` or just `ip` for default port 53) (nullable - uses default from RedirectorConfig if not specified)
- `DNSProxy`: Whether to proxy DNS requests (nullable - uses default from RedirectorConfig if not specified)
- `HandleOnlyDNS`: Whether to only handle DNS (not redirect other traffic) (nullable - uses default from RedirectorConfig if not specified)
- `ICMPDelay`: ICMP delay in milliseconds (nullable - uses default from RedirectorConfig if not specified)
- `LocalProxyPort`: Local proxy server port that the kernel driver redirects intercepted connections to (default: 8888). This is the port where OmniPoss's local TCP proxy listens.
- `Bypass`: List of wildcard patterns for applications to bypass (see [Bypass Rules](#bypass-rules))
- `Handle`: List of wildcard patterns for applications to redirect (see [Handle Rules](#handle-rules))

## 📖 Example: Using sing-box with TUIC

1. **Download sing-box**: Place `sing-box.exe` in `data/cores/`

2. **Create sing-box config** (`data/cores/sing-box.json`):
```json
{
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "users": []
    }
  ],
  "outbounds": [
    {
      "type": "tuic",
      "tag": "tuic-out",
      "server": "your-server.com",
      "server_port": 443,
      "uuid": "your-uuid",
      "password": "your-password",
      "congestion_control": "bbr"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": "socks-in",
        "outbound": "tuic-out"
      }
    ]
  }
}
```

3. **Configure OmniPoss** (`data/configs.json`):
```json
{
  "AutoStart": true,
  "Cores": [
    {
      "Key": "sing-box",
      "ExePath": "data/cores/sing-box.exe",
      "Argument": "-c data/cores/sing-box.json",
      "Enabled": true
    }
  ],
  "Socks5ServerConfig": {
    "Hostname": "127.0.0.1",
    "Port": 1080
  },
  "NFConfig": {
    "Enabled": true
  }
}
```

4. **Start OmniPoss**: The application will launch sing-box and route all system traffic through it.

## 🎮 System Tray Menu

Right-click the OmniPoss tray icon to access:

- **NF Run/Stop**: Start or stop the OmniPoss service (network filtering)
- **Proxy Enable/Disable**: Configure Windows system-wide proxy
- **Console Show/Hide**: Toggle console window visibility
- **Cores**: Submenu to start/stop individual cores
- **Reload**: Hot-reload configuration from disk
- **Open config folder**: Open `data/` folder in Explorer
- **Open cores folder**: Open `data/cores/` folder in Explorer
- **Exit**: Gracefully shutdown the application

## 📝 Logging

OmniPoss uses Serilog for structured logging:

- **Console**: Logs are displayed in the console window (when visible)
- **File**: Logs are written to `data/logs/omniposs-YYYYMMDD.log`
- **Retention**: Log files are retained for 7 days (rolling daily)

Log levels: Debug, Information, Warning, Error, Fatal

## 🔧 Advanced Usage

### Hot-Reload

OmniPoss supports hot-reloading configuration without restarting:

1. Edit `data/configs.json` with your changes
2. Right-click tray icon → **Reload**
3. Running services will be updated if their config changed
4. Cores will be restarted to pick up external config changes

**Note**: This is a RELOAD, not a RESTART. Services that are not running will not be started.

**Hot-Reload Implementation**:
- Reads actual running state before reload
- Updates in-memory config objects (preserves references)
- Only restarts services that are running AND have config changes
- Relaunches all running cores (to pick up external config changes)
- Properly disposes and recreates proxy connections for seamless reload
- Supports socket reuse to handle ports in TIME_WAIT state

### Bypass Rules

Use process name patterns in `NFConfig.Bypass` to exclude applications from filtering. Uses the same **wildcard matching** as Handle rules:

```json
{
  "NFConfig": {
    "Bypass": [
      "*chrome.exe",
      "*Discord*",
      "*firefox.exe"
    ]
  }
}
```

**Note**: Bypass rules have higher priority than Handle rules. If a process matches a Bypass pattern, it will not be redirected even if it also matches a Handle pattern.

### Handle Rules

Use process name patterns in `NFConfig.Handle` to explicitly include applications for redirection. NetFilter SDK uses **wildcard matching** (not full regex):

**Wildcard Matching Rules:**
- **Matching**: Done from the **tail (end)** of the process name
- **Case-insensitive**: Matching ignores case differences
- **Wildcard**: Use `*` to match 0 or more characters
- **Examples**:
  - `"chrome.exe"` - Matches processes ending with "chrome.exe" (e.g., `C:\Program Files\Google\Chrome\Application\chrome.exe`)
  - `"*Discord*"` - Matches any process name containing "Discord"
  - `"*Discord.exe"` - Matches processes ending with "Discord.exe"
  - `"Discord"` - Matches processes ending with "Discord" (may not match "Discord.exe" if the process name includes the extension)

**Important**: Patterns are matched against the process name (without full path). Use wildcards to match partial names or handle variations.

```json
{
  "NFConfig": {
    "Handle": [
      "*chrome.exe",
      "*Discord*",
      "*firefox.exe"
    ]
  }
}
```

**Note**: If `Handle` is empty or not specified, all processes will be redirected (when `Enabled` is true). If `Handle` contains patterns, only processes matching those patterns will be redirected.

### UDP Proxying

OmniPoss uses **SOCKS5 UDP ASSOCIATE** method for UDP traffic proxying:

- **TCP Control Channel**: Each UDP connection creates a TCP control channel for SOCKS5 UDP ASSOCIATE negotiation
- **UDP Data Transfer**: After negotiation, UDP packets are sent through the SOCKS5 relay
- **Address Extraction**: Original destination IP/port is extracted from SOCKS5 UDP header
- **Connection Tracking**: UDP connections are tracked by endpoint ID and cleaned up automatically
- **Race Condition Protection**: Checks connection existence before posting data back to prevent errors

This implementation follows the NetFilter SDK WFP sample pattern for reliable UDP proxying.

## 🛠️ Development

### Building

```bash
dotnet build -c Release
```

### Project Structure

- `Program.cs`: Application entry point, UAC elevation, logging setup, DI container
- `Core/`: Main business logic and application lifecycle
  - `ApplicationHost.cs`: Central orchestrator, hot-reload, tray menu, graceful shutdown
  - `MainController.cs`: Orchestrates SOCKS5 client and network filter controller
  - `NetworkFilterController.cs`: Manages redirector configuration
- `Configuration/`: All configuration models
  - `ApplicationConfig.cs`: Root configuration container
  - `NFConfig.cs`: Network filter configuration
  - `ProxyConfig.cs`: System proxy settings
  - `CoreConfig.cs`: Core process definition
- `Infrastructure/`: Platform-specific code
  - `Drivers/NetworkFilterDriver.cs`: Driver installation and management
  - `Interop/Redirector.cs`: Pure C# implementation for driver control (uses nfapi.dll directly)
  - `Process/CoreProcessManager.cs`: Process lifecycle management
- `Services/`: Service layer
  - `Socks5ClientService.cs`: SOCKS5 client wrapper
  - `ProxyService.cs`: Windows registry-based proxy configuration
- `Interop/`: Network proxy implementations
  - `LocalTcpProxy.cs`: Local TCP proxy server (SOCKS5, configurable port, default 8888)
  - `LocalUdpProxy.cs`: Local UDP proxy handler (SOCKS5 UDP ASSOCIATE)
  - `ConsoleManager.cs`: Console window show/hide management
- `UI/`: User interface components
  - `Tray/TrayMenu.cs`: Context menu creation and state management
  - `ShutdownHandlerForm.cs`: Hidden form for Windows shutdown signal handling
- `Utilities/`: Utility classes
  - `FirewallUtils.cs`: Windows Firewall rule management
  - `DnsUtils.cs`: DNS resolution utilities
  - `PortUtils.cs`: Port availability checking
  - `Socks5TestUtils.cs`: NAT type testing, HTTP connectivity tests
- `Storage/`: Native binaries and drivers (source files)
  - `v2.0/`: Current version (used in production)
  - `v1.0/`: Legacy version (kept for compatibility)

### Dependencies

**NuGet Packages**:
- .NET 9.0
- Microsoft.Extensions.DependencyInjection (v9.0.0)
- Serilog (v4.1.0) - Structured logging
- Serilog.Sinks.Console (v6.0.0) - Console logging
- Serilog.Sinks.File (v6.0.0) - File logging
- Newtonsoft.Json (v13.0.3) - Configuration serialization
- Socks5 (v1.0.2) - SOCKS5 protocol support
- Stun.Net (v9.0.0) - NAT type testing
- WindowsFirewallHelper (v2.2.0.86) - Firewall rule management
- Microsoft.Windows.CsWin32 (v0.3.183) - Windows API bindings
- Microsoft.VisualStudio.Threading (v17.14.15) - Async utilities

**Native Components**:
- **NetFilterSDK** (proprietary) - Kernel-mode network filter driver and native API
  - Components: `nfapi.dll`, `nfdriver.sys`, `nfregdrv.exe`
  - Location: `Storage/v2.0/` (copied to `bin/` on build)
  - License: Proprietary (see [NetFilterSDK License](https://www.netfiltersdk.com/license.html))
  - Note: NetFilterSDK components are NOT covered by this project's MIT License

## ⚠️ Important Notes

- **Administrator Privileges**: Required for driver installation and network interception
- **Driver Installation**: The kernel driver (`netfilter2.sys`) is automatically installed to `%SystemRoot%\drivers\` on first run. The driver is automatically upgraded if a newer version is detected.
- **Firewall Rules**: Automatically managed by the application (added on start, removed on stop)
- **Single Instance**: Only one instance can run at a time (enforced via mutex `Global\OmniPoss`)
- **Core Configuration**: Each core uses its own native configuration format (JSON, etc.)
- **UDP Proxying**: Uses SOCKS5 UDP ASSOCIATE method for UDP traffic proxying through SOCKS5 relay
- **Windows Shutdown**: Application handles Windows shutdown signals gracefully, ensuring proper cleanup of drivers, processes, and resources
- **Auto-Start**: Release builds automatically create a startup shortcut in the Windows Startup folder

## 🐛 Troubleshooting

### Driver Installation Fails
- Ensure you're running as administrator
- Check Windows Event Viewer for driver errors
- Verify `bin/nfdriver.sys` exists (copied from `Storage/v2.0/`)

### Core Not Starting
- Check `data/logs/omniposs-*.log` for errors
- Verify core executable path in `configs.json`
- Ensure core's config file exists and is valid
- Check console output (toggle via tray menu)

### Traffic Not Being Intercepted
- Verify OmniPoss service is running (tray menu: "NF Run")
- Check `NFConfig.Enabled` is `true`
- Verify SOCKS5 endpoint matches core's SOCKS5 server address
- Check bypass/handle rules aren't excluding your application

### DNS Issues
- Verify `DNSHost` is correct (format: `ip:port`)
- Check `DNSProxy` and `HandleOnlyDNS` settings
- Ensure DNS server is reachable
- DNS resolution is cached to prevent "Wrong STUN Server" errors

### Port Conflicts
- Local TCP proxy listens on port 8888 by default (configurable via `NFConfig.LocalProxyPort`)
- Ensure the configured port is not in use by another application
- Port conflicts are automatically resolved during hot-reload (socket reuse enabled)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Important**: This project includes NetFilterSDK components (nfapi.dll, nfdriver.sys, Redirector.bin) which are proprietary and subject to their own license terms. The MIT License applies only to the OmniPoss project's own source code, not to NetFilterSDK components. See the [LICENSE](LICENSE) file for complete details and NetFilterSDK licensing information.

## 🙏 Acknowledgments

OmniPoss was originally created to support the **TUIC protocol**, which was unsupported by all proxy clients at the time. The architecture enables support for any protocol that proxy cores support, making it future-proof and highly flexible.

This project uses **NetFilterSDK** by Vitaly Sidorov for kernel-mode network traffic interception. NetFilterSDK is proprietary software - for licensing information, please visit [netfiltersdk.com](https://www.netfiltersdk.com/).

## 📚 Additional Documentation

- [AI Context](Documents/AI_CONTEXT.md) - Detailed technical documentation for developers
- [Deployment Guide](Documents/Deploy.md) - Deployment and installation instructions
