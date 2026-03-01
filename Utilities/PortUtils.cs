using OmniPoss.Models;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using OmniPoss.Infrastructure.Interop;

namespace OmniPoss.Utilities
{
    /// <summary>
    /// Port availability and process detection utilities.
    /// Provides methods to check port usage and find processes using specific ports.
    /// </summary>
    internal static class PortUtils
    {
        private static readonly List<NumberRange> TCPReservedRanges = [];
        private static readonly List<NumberRange> UDPReservedRanges = [];
        private static readonly IPGlobalProperties NetInfo = IPGlobalProperties.GetIPGlobalProperties();

        static PortUtils()
        {
            try
            {
                GetReservedPortRange(PortType.TCP, ref TCPReservedRanges);
                GetReservedPortRange(PortType.UDP, ref UDPReservedRanges);
            }
            catch
            {

            }
        }

        /// <summary>
        /// Gets processes listening on the specified TCP port.
        /// </summary>
        /// <param name="port">TCP port number.</param>
        /// <param name="inet">Address family (default: InterNetwork).</param>
        /// <returns>Enumerable of processes using the port.</returns>
        internal static IEnumerable<Process> GetProcessByUsedTcpPort(ushort port, AddressFamily inet = AddressFamily.InterNetwork)
        {
            if (port == 0)
                throw new ArgumentOutOfRangeException();

            switch (inet)
            {
                case AddressFamily.InterNetwork:
                    {
                        var process = new List<Process>();
                        uint size = 0;
                        NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, (uint)inet, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_LISTENER, 0);
                        var buffer = Marshal.AllocHGlobal((int)size);
                        try
                        {
                            var err = NativeMethods.GetExtendedTcpTable(buffer, ref size, false, (uint)inet, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_LISTENER, 0);
                            if (err != 0)
                                throw new Win32Exception((int)err);

                            var numEntries = (uint)Marshal.ReadInt32(buffer, 0);
                            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                            for (var i = 0; i < numEntries; i++)
                            {
                                var rowPtr = IntPtr.Add(buffer, 4 + i * rowSize);
                                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                                if (row.dwOwningPid is 0 or 4)
                                    continue;

                                var localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort);
                                if (localPort == port)
                                    process.Add(Process.GetProcessById((int)row.dwOwningPid));
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(buffer);
                        }

                        return process;
                    }
                case AddressFamily.InterNetworkV6:
                    throw new NotImplementedException();
                default:
                    throw new InvalidOperationException();
            }
        }
        private static void GetReservedPortRange(PortType portType, ref List<NumberRange> targetList)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $" int ipv4 show excludedportrange {portType}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();

            foreach (var line in SplitRemoveEmptyEntriesAndTrimEntries(output, '\n'))
            {
                var value = SplitRemoveEmptyEntries(line.Trim(), ' ');
                if (value.Length < 2)
                    continue;

                if (!ushort.TryParse(value[0], out var start) || !ushort.TryParse(value[1], out var end))
                    continue;

                targetList.Add(new NumberRange(start, end));
            }
        }
        public static void CheckPort(ushort port, PortType type = PortType.Both)
        {
            switch (type)
            {
                case PortType.Both:
                    CheckPort(port, PortType.TCP);
                    CheckPort(port, PortType.UDP);
                    break;
                default:
                    CheckPortInUse(port, type);
                    CheckPortReserved(port, type);
                    break;
            }
        }
        private static void CheckPortInUse(ushort port, PortType type)
        {
            switch (type)
            {
                case PortType.Both:
                    CheckPortInUse(port, PortType.TCP);
                    CheckPortInUse(port, PortType.UDP);
                    break;
                case PortType.TCP:
                    if (NetInfo.GetActiveTcpListeners().Any(ipEndPoint => ipEndPoint.Port == port))
                        throw new Exception();

                    break;
                case PortType.UDP:
                    if (NetInfo.GetActiveUdpListeners().Any(ipEndPoint => ipEndPoint.Port == port))
                        throw new Exception();

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
        private static void CheckPortReserved(ushort port, PortType type)
        {
            switch (type)
            {
                case PortType.Both:
                    CheckPortReserved(port, PortType.TCP);
                    CheckPortReserved(port, PortType.UDP);
                    return;
                case PortType.TCP:
                    if (TCPReservedRanges.Any(range => range.InRange(port)))
                        throw new Exception();

                    break;
                case PortType.UDP:
                    if (UDPReservedRanges.Any(range => range.InRange(port)))
                        throw new Exception();

                    break;
                default:
                    Trace.Assert(false);
                    return;
            }
        }
        public static ushort GetAvailablePort(PortType portType = PortType.Both)
        {
            var random = new Random();
            for (ushort i = 0; i < 55535; i++)
            {
                var p = (ushort)random.Next(10000, 65535);
                try
                {
                    CheckPort(p, portType);
                    return p;
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            throw new Exception();
        }

        private static string[] SplitRemoveEmptyEntriesAndTrimEntries(string value, params char[] separator)
        {
            return value.Split(separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        private static string[] SplitRemoveEmptyEntries(string value, params char[] separator)
        {
            return value.Split(separator, StringSplitOptions.RemoveEmptyEntries);
        }
    }

    [Flags]
    public enum PortType
    {
        TCP = 0b_01,
        UDP = 0b_10,
        Both = TCP | UDP
    }
}
