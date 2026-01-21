using System.Runtime.InteropServices;

namespace OmniPoss.Interop
{
    internal partial class Redirector
    {
        public enum NameList
        {
            AIO_FILTERLOOPBACK,
            AIO_FILTERINTRANET, // LAN
            AIO_FILTERPARENT,
            AIO_FILTERICMP,
            AIO_FILTERTCP,
            AIO_FILTERUDP,
            AIO_FILTERDNS,

            AIO_ICMPING,

            AIO_DNSONLY,
            AIO_DNSPROX,
            AIO_DNSHOST,
            AIO_DNSPORT,

            AIO_TGTHOST,
            AIO_TGTPORT,
            AIO_TGTUSER,
            AIO_TGTPASS,

            AIO_CLRNAME,
            AIO_ADDNAME,
            AIO_BYPNAME
        }

        public static bool Dial(NameList name, bool value)
        {
            return aio_dial(name, value.ToString().ToLower());
        }

        public static bool Dial(NameList name, string value)
        {
            return aio_dial(name, value);
        }

        public static Task<bool> InitAsync()
        {
            return Task.Run(aio_init);
        }

        public static Task<bool> FreeAsync()
        {
            return Task.Run(aio_free);
        }

        private const string Redirector_bin = "Redirector.bin";

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool aio_register([MarshalAs(UnmanagedType.LPWStr)] string value);

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static partial bool aio_unregister([MarshalAs(UnmanagedType.LPWStr)] string value);

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool aio_dial(NameList name, [MarshalAs(UnmanagedType.LPWStr)] string value);

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool aio_init();

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool aio_free();

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        private static partial ulong aio_getUP();

        [LibraryImport(Redirector_bin)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        private static partial ulong aio_getDL();
    }
}
