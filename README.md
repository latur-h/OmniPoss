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
   - Intercepts and redirects TCP/UDP/DNS traffic at the kernel level using a Windows driver
   - Acts as a SOCKS5 client connecting to cores' SOCKS5 servers
   - Manages the kernel driver, firewall rules, and system proxy settings

2. **Core Layer (Any Protocol)**:
   - External executable processes (sing-box, xray, v2ray, or any proxy core)
   - Each core runs independently with its own configuration
   - Cores listen on local ports and handle their specific protocols
   - Cores expose SOCKS5 servers that OmniPoss connects to

3. **Traffic Flow**:
   ```
   Application → Kernel Driver → OmniPoss SOCKS5 Client → Core SOCKS5 Server → Core Protocol Handler → Upstream Server
   ```

## 📋 Requirements

- **OS**: Windows 10.0.17763.0 or later
- **Architecture**: x64 or ARM64
- **Privileges**: Administrator (required for driver installation)
- **.NET**: 9.0 runtime

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
- `FilterTCP`, `FilterUDP`, `FilterDNS`, `FilterICMP`: Protocol filtering
- `FilterLoopback`, `FilterIntranet`, `FilterParent`: Network scope filtering
- `DNSHost`: DNS server address (format: `ip:port`)
- `DNSProxy`: Whether to proxy DNS requests
- `HandleOnlyDNS`: Whether to only handle DNS (not redirect other traffic)
- `ICMPDelay`: ICMP delay in milliseconds
- `Bypass`: List of regex patterns for applications to bypass
- `Handle`: List of regex patterns for applications to redirect

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

### Bypass Rules

Use regex patterns in `NFConfig.Bypass` to exclude applications from filtering:

```json
{
  "NFConfig": {
    "Bypass": [
      "^C:\\\\Program Files\\\\MyApp",
      ".*\\.exe$"
    ]
  }
}
```

### Handle Rules

Use regex patterns in `NFConfig.Handle` to explicitly include applications:

```json
{
  "NFConfig": {
    "Handle": [
      "^C:\\\\Program Files\\\\Browser",
      "chrome\\.exe$"
    ]
  }
}
```

## 🛠️ Development

### Building

```bash
dotnet build -c Release
```

### Project Structure

- `Core/`: Main business logic and application lifecycle
- `Configuration/`: Configuration models
- `Infrastructure/`: Platform-specific code (drivers, interop, process management)
- `Services/`: Service layer (SOCKS5 client, proxy service)
- `UI/`: User interface components (tray menu, shutdown handler)
- `Utilities/`: Utility classes (firewall, DNS, port checking, etc.)
- `Storage/`: Native binaries and drivers

### Dependencies

- .NET 9.0
- Microsoft.Extensions.DependencyInjection
- Serilog (logging)
- Newtonsoft.Json (configuration)
- Socks5 (SOCKS5 protocol)
- Stun.Net (NAT type testing)
- WindowsFirewallHelper (firewall management)
- **NetFilterSDK** (proprietary) - Kernel-mode network filter driver and native API
  - Components: `nfapi.dll`, `nfdriver.sys`, `Redirector.bin`
  - License: Proprietary (see [NetFilterSDK License](https://www.netfiltersdk.com/license.html))
  - Note: NetFilterSDK components are NOT covered by this project's MIT License

## ⚠️ Important Notes

- **Administrator Privileges**: Required for driver installation and network interception
- **Driver Installation**: The kernel driver (`netfilter2.sys`) is automatically installed to `%SystemRoot%\drivers\`
- **Firewall Rules**: Automatically managed by the application
- **Single Instance**: Only one instance can run at a time (enforced via mutex)
- **Core Configuration**: Each core uses its own native configuration format (JSON, etc.)

## 🐛 Troubleshooting

### Driver Installation Fails
- Ensure you're running as administrator
- Check Windows Event Viewer for driver errors
- Verify `Storage/nfdriver.sys` exists

### Core Not Starting
- Check `data/logs/netfilter-*.log` for errors
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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Important**: This project includes NetFilterSDK components (nfapi.dll, nfdriver.sys, Redirector.bin) which are proprietary and subject to their own license terms. The MIT License applies only to the OmniPoss project's own source code, not to NetFilterSDK components. See the [LICENSE](LICENSE) file for complete details and NetFilterSDK licensing information.

## 🙏 Acknowledgments

OmniPoss was originally created to support the **TUIC protocol**, which was unsupported by all proxy clients at the time. The architecture enables support for any protocol that proxy cores support, making it future-proof and highly flexible.

This project uses **NetFilterSDK** by Vitaly Sidorov for kernel-mode network traffic interception. NetFilterSDK is proprietary software - for licensing information, please visit [netfiltersdk.com](https://www.netfiltersdk.com/).

## 📚 Additional Documentation

- [AI Context](Documents/AI_CONTEXT.md) - Detailed technical documentation for developers
- [Deployment Guide](Documents/Deploy.md) - Deployment and installation instructions
