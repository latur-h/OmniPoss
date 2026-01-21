namespace OmniPoss.Configuration
{
    internal class CoreConfig(string key, string exePath, string args)
    {
        public bool Enabled { get; set; } = false;

        public string Key = key;
        public string ExePath = exePath;
        public string Argument = args;
    }
}
