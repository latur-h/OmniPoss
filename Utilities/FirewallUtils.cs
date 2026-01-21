using WindowsFirewallHelper;
using WindowsFirewallHelper.FirewallRules;

namespace OmniPoss.Utilities
{
    /// <summary>
    /// Windows Firewall rule management utilities.
    /// Automatically adds firewall rules for NetFilter executables.
    /// </summary>
    internal class FirewallUtils
    {
        private const string NetFilter = "OmniPoss";

        /// <summary>
        /// Adds Windows Firewall rules for all NetFilter executables in the current directory.
        /// </summary>
        public static void AddNetFilterFwRules()
        {
            if (!FirewallWAS.IsLocallySupported)
            {
                return;
            }

            string dir = Environment.CurrentDirectory;

            try
            {
                var rule = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == NetFilter);
                if (rule != null)
                {
                    if (rule.ApplicationName.StartsWith(dir))
                        return;

                    RemoveNetFilterFwRules();
                }

                foreach (var path in Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories))
                    AddFwRule(NetFilter, path);
            }
            catch
            {

            }
        }
        /// <summary>
        /// Removes Windows Firewall rules for NetFilter.
        /// </summary>
        public static void RemoveNetFilterFwRules()
        {
            if (!FirewallWAS.IsLocallySupported)
                return;

            string dir = Environment.CurrentDirectory;

            try
            {
                foreach (var rule in FirewallManager.Instance.Rules.Where(r
                             => r.ApplicationName?.StartsWith(dir, StringComparison.OrdinalIgnoreCase) ?? r.Name == NetFilter))
                    FirewallManager.Instance.Rules.Remove(rule);
            }
            catch
            {

            }
        }
        private static void AddFwRule(string ruleName, string exeFullPath)
        {
            var rule = new FirewallWASRule(ruleName,
                exeFullPath,
                FirewallAction.Allow,
                FirewallDirection.Inbound,
                FirewallProfiles.Private | FirewallProfiles.Public | FirewallProfiles.Domain);

            FirewallManager.Instance.Rules.Add(rule);
        }
    }
}
