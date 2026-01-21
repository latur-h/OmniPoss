using OmniPoss.Configuration;

namespace OmniPoss.UI.Tray
{
    internal class TrayMenu
    {
        private ToolStripMenuItem? Cores;
        private ToolStripMenuItem? NetFilter;
        private ToolStripMenuItem? Proxy;
        private ToolStripMenuItem? Console;
        private ToolStripMenuItem? OpenConfig;
        private ToolStripMenuItem? OpenCores;
        private ToolStripMenuItem? Reload;
        private ToolStripMenuItem? Exit;

        public ContextMenuStrip Init(List<CoreConfig> cores, bool nf, bool proxy)
        {
            ContextMenuStrip contextMenuStrip = new();

            Cores = new("Cores") { Name = "Cores" };
            foreach (CoreConfig core in cores)
            {
                ToolStripMenuItem _core = new(core.Key) { Name = core.Key, CheckOnClick = true, Checked = core.Enabled };

                Cores.DropDownItems.Add(_core);
            }

            Reload = new("Reload") { Name = "Reload" };

            NetFilter = new(nf ? "NF Stop" : "NF Run") { Name = "NF" };
            Proxy = new(proxy ? "Proxy Disable" : "Proxy Enable") { Name = "Proxy" };

            Console = new("Console Show") { Name = "Console" };
            Exit = new("Exit") { Name = "Exit" };
            OpenConfig = new("Open config folder") { Name = "OpenConfigFolder" };
            OpenCores = new("Open cores folder") { Name = "OpenCoresFolder" };

            contextMenuStrip.Items.AddRange(Reload, Cores, NetFilter, Proxy, Console, OpenConfig, OpenCores, Exit);

            return contextMenuStrip;
        }

        public void ToggleNetFilter(bool isRunning)
        {
            if (NetFilter == null) return;
            if (isRunning) NetFilter.Text = "NF Stop";
            else NetFilter.Text = "NF Run";
        }
        public void ToggleConsole(bool isRunning)
        {
            if (Console == null) return;
            if (isRunning) Console.Text = "Console Hide";
            else Console.Text = "Console Show";
        }
        public void ToggleProxy(bool isRunning)
        {
            if (Proxy == null) return;
            if (isRunning) Proxy.Text = "Proxy Disable";
            else Proxy.Text = "Proxy Enable";
        }
        public void ToggleCore(string key, bool isEnabled)
        {
            if (Cores == null || !Cores.DropDownItems.ContainsKey(key)) return;

            var item = Cores.DropDownItems[key];
            if (item != null)
            {
                if (isEnabled) item.Text = $"{key}   ✓";
                else item.Text = key;
            }
        }
    }
}
