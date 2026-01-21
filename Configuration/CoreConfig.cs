namespace OmniPoss.Configuration
{
    /// <summary>
    /// Configuration for an external proxy core process (sing-box, xray, v2ray, etc.).
    /// </summary>
    internal class CoreConfig(string key, string exePath, string args)
    {
        /// <summary>
        /// Whether to automatically start this core on application launch.
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Unique identifier for this core (used for process tracking and tray menu).
        /// </summary>
        public string Key = key;

        /// <summary>
        /// Path to the core executable file (e.g., "data/cores/sing-box.exe").
        /// </summary>
        public string ExePath = exePath;

        /// <summary>
        /// Command-line arguments for the core (often includes path to core's config file).
        /// </summary>
        public string Argument = args;
    }
}
