using System.Collections;
using System.Net;
using System.Net.Sockets;

namespace OmniPoss.Utilities
{
    internal static class DnsUtils
    {
        private static readonly SemaphoreSlim Lock = new(1);

        private static readonly Hashtable Cache = [];
        private static readonly Hashtable Cache6 = [];

        public static async Task<IPAddress?> LookupAsync(string hostname, AddressFamily inet = AddressFamily.Unspecified, int timeout = 3000)
        {
            await Lock.WaitAsync();
            try
            {
                var cacheResult = inet switch
                {
                    AddressFamily.Unspecified => (IPAddress?)(Cache[hostname] ?? Cache6[hostname]),
                    AddressFamily.InterNetwork => (IPAddress?)Cache[hostname],
                    AddressFamily.InterNetworkV6 => (IPAddress?)Cache6[hostname],
                    _ => throw new ArgumentOutOfRangeException()
                };

                if (cacheResult != null)
                    return cacheResult;

                return await LookupNoCacheAsync(hostname, inet, timeout);
            }
            catch
            {
                return null;
            }
            finally
            {
                Lock.Release();
            }
        }
        private static async Task<IPAddress?> LookupNoCacheAsync(string hostname, AddressFamily inet = AddressFamily.Unspecified, int timeout = 3000)
        {
            using var task = Dns.GetHostAddressesAsync(hostname);
            using var resTask = await Task.WhenAny(task, Task.Delay(timeout));

            if (resTask == task)
            {
                var addresses = await task;

                var result = addresses.FirstOrDefault(i => inet == AddressFamily.Unspecified || inet == i.AddressFamily);
                if (result == null)
                    return null;

                switch (result.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        Cache.Add(hostname, result);
                        break;
                    case AddressFamily.InterNetworkV6:
                        Cache6.Add(hostname, result);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                return result;
            }

            return null;
        }
        public static void ClearCache()
        {
            Cache.Clear();
            Cache6.Clear();
        }

        public static string AppendPort(string host, ushort port = 53)
        {
            if (!host.Contains(':'))
                return host + $":{port}";

            return host;
        }
    }
}
