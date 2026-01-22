using OmniPoss.Configuration;
using System.Drawing;
using System.Windows.Forms;

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
        private ToolStripMenuItem? StartWithWindows;
        private ToolStripMenuItem? Exit;

        public ContextMenuStrip Init(List<CoreConfig> cores, bool nf, bool proxy, bool autoStart, Func<string, bool>? isCoreRunning = null)
        {
            ContextMenuStrip contextMenuStrip = new();
            contextMenuStrip.Renderer = new ColoredMenuRenderer();

            Cores = new("Cores") { Name = "Cores" };
            foreach (CoreConfig core in cores)
            {
                bool isRunning = isCoreRunning?.Invoke(core.Key) ?? false;
                ToolStripMenuItem _core = new(core.Key) { Name = core.Key, Tag = isRunning };
                Cores.DropDownItems.Add(_core);
            }

            Reload = new("Reload") { Name = "Reload" };

            NetFilter = new(nf ? "NF Stop" : "NF Run") { Name = "NF", Tag = nf };
            Proxy = new(proxy ? "Proxy Disable" : "Proxy Enable") { Name = "Proxy", Tag = proxy };

            Console = new("Console Show") { Name = "Console" };
            StartWithWindows = new("Start with Windows") { Name = "StartWithWindows", Tag = autoStart };
            Exit = new("Exit") { Name = "Exit" };
            OpenConfig = new("Open config folder") { Name = "OpenConfigFolder" };
            OpenCores = new("Open cores folder") { Name = "OpenCoresFolder" };

            contextMenuStrip.Items.AddRange(Reload, Cores, NetFilter, Proxy, Console, StartWithWindows, OpenConfig, OpenCores, Exit);

            return contextMenuStrip;
        }

        public void ToggleNetFilter(bool isRunning)
        {
            if (NetFilter == null) return;
            NetFilter.Tag = isRunning;
            if (isRunning) NetFilter.Text = "NF Stop";
            else NetFilter.Text = "NF Run";
            NetFilter.Invalidate();
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
            Proxy.Tag = isRunning;
            if (isRunning) Proxy.Text = "Proxy Disable";
            else Proxy.Text = "Proxy Enable";
            Proxy.Invalidate();
        }
        public void ToggleCore(string key, bool isRunning)
        {
            if (Cores == null || !Cores.DropDownItems.ContainsKey(key)) return;

            var item = Cores.DropDownItems[key] as ToolStripMenuItem;
            if (item != null)
            {
                item.Tag = isRunning;
                item.Text = key;
                item.Invalidate();
            }
        }
        public void ToggleStartWithWindows(bool isEnabled)
        {
            if (StartWithWindows == null) return;
            StartWithWindows.Tag = isEnabled;
            StartWithWindows.Text = "Start with Windows";
            StartWithWindows.Invalidate();
        }
    }

    internal class ColoredMenuRenderer : ToolStripProfessionalRenderer
    {
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            if (e.Item is ToolStripMenuItem menuItem && menuItem.Tag is bool isEnabled)
            {
                Color circleColor = isEnabled ? Color.FromArgb(46, 204, 113) : Color.FromArgb(231, 76, 60);

                int circleSize = 10;
                int circleX = e.TextRectangle.X;
                int circleY = e.TextRectangle.Y + (e.TextRectangle.Height - circleSize) / 2;

                using (var brush = new SolidBrush(circleColor))
                {
                    e.Graphics.FillEllipse(brush, circleX, circleY, circleSize, circleSize);
                }

                var textRect = e.TextRectangle;
                textRect.X += circleSize + 4;

                var newArgs = new ToolStripItemTextRenderEventArgs(
                    e.Graphics,
                    e.Item,
                    e.Text,
                    textRect,
                    e.TextColor,
                    e.TextFont,
                    e.TextFormat);

                base.OnRenderItemText(newArgs);
            }
            else
            {
                base.OnRenderItemText(e);
            }
        }
    }
}
