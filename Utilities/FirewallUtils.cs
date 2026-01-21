using WindowsFirewallHelper;
using WindowsFirewallHelper.FirewallRules;

namespace OmniPoss.Utilities
{
    internal class FirewallUtils
    {
        private const string OmniPoss = "OmniPoss";

        public static void AddOmniPossFwRules()
        {
            if (!FirewallWAS.IsLocallySupported)
            {
                return;
            }

            string dir = Environment.CurrentDirectory;

            try
            {
                var rule = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == OmniPoss);
                if (rule != null)
                {
                    if (rule.ApplicationName.StartsWith(dir))
                        return;

                    RemoveOmniPossFwRules();
                }

                foreach (var path in Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories))
                    AddFwRule(OmniPoss, path);
            }
            catch
            {

            }
        }
        public static void RemoveOmniPossFwRules()
        {
            if (!FirewallWAS.IsLocallySupported)
                return;

            string dir = Environment.CurrentDirectory;

            try
            {
                foreach (var rule in FirewallManager.Instance.Rules.Where(r
                             => r.ApplicationName?.StartsWith(dir, StringComparison.OrdinalIgnoreCase) ?? r.Name == OmniPoss))
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
