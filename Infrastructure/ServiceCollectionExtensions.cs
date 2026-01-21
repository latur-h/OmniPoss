using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using OmniPoss.Configuration;
using OmniPoss.Core;
using OmniPoss.Infrastructure.Drivers;
using OmniPoss.Infrastructure.Process;
using OmniPoss.Services;
using OmniPoss.Servers;
using OmniPoss.UI.Tray;

namespace OmniPoss.Infrastructure
{
    /// <summary>
    /// Extension methods for configuring dependency injection services.
    /// </summary>
    internal static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers all application services with the dependency injection container.
        /// </summary>
        public static IServiceCollection AddNetFilterServices(this IServiceCollection services, ApplicationConfig config)
        {
            // Register logging (Serilog is already configured in Program.cs)
            services.AddLogging(builder => builder.AddSerilog());

            // Register configuration
            services.AddSingleton(config);
            services.AddSingleton(config.NFConfig);
            services.AddSingleton(config.Socks5ServerConfig);
            // ProxyConfig is a struct, access it via ApplicationConfig
            services.AddSingleton(config.Cores);

            // Register infrastructure services
            services.AddSingleton<NetworkFilterDriver>(sp =>
            {
                var logger = sp.GetRequiredService<ILogger<NetworkFilterDriver>>();
                return new NetworkFilterDriver(logger);
            });
            services.AddSingleton<CoreProcessManager>(sp =>
            {
                var cores = sp.GetRequiredService<List<CoreConfig>>();
                var logger = sp.GetRequiredService<ILogger<CoreProcessManager>>();
                return new CoreProcessManager(cores, logger);
            });

            // Register core services
            services.AddSingleton<MainController>(sp =>
            {
                var socks5Server = sp.GetRequiredService<Socks5ClientService>();
                var controller = sp.GetRequiredService<NetworkFilterController>();
                var logger = sp.GetRequiredService<ILogger<MainController>>();
                return new MainController(socks5Server, controller, logger);
            });

            services.AddSingleton<NetworkFilterController>(sp =>
            {
                var nfConfig = sp.GetRequiredService<NFConfig>();
                var driverManager = sp.GetRequiredService<NetworkFilterDriver>();
                var logger = sp.GetRequiredService<ILogger<NetworkFilterController>>();
                return new NetworkFilterController(nfConfig, driverManager, logger);
            });

            // Register application services
            services.AddSingleton<ProxyService>(sp =>
            {
                var logger = sp.GetRequiredService<ILogger<ProxyService>>();
                return new ProxyService(logger);
            });
            services.AddSingleton<Socks5ClientService>(sp =>
            {
                var config = sp.GetRequiredService<Socks5ClientConfig>();
                return new Socks5ClientService(config);
            });

            // Register UI services
            services.AddSingleton<TrayMenu>();

            return services;
        }
    }
}
