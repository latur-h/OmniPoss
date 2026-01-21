using System.Diagnostics;

namespace OmniPoss.Utilities
{
    internal static class GeneralUtils
    {
        public static string GetFileVersion(string file)
        {
            if (File.Exists(file))
                return FileVersionInfo.GetVersionInfo(file).FileVersion ?? "";

            return "";
        }
    }
}
