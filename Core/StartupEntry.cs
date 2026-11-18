using System;
using System.Reflection;
using Microsoft.Win32;

namespace SecHUD
{
    /// <summary>"Start with Windows": one value under the current user's Run key. No admin needed.</summary>
    public static class StartupEntry
    {
        private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string ValueName = "SecHUD";

        /// <summary>The key the autorun watch will see for this entry, so it can be pre-approved.</summary>
        public static string AutorunKey
        {
            get { return "run|HKCU\\" + ValueName + "|" + Command; }
        }

        private static string Command
        {
            get { return "\"" + Assembly.GetExecutingAssembly().Location + "\" --tray"; }
        }

        public static bool IsEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunPath))
                {
                    return key != null && key.GetValue(ValueName) != null;
                }
            }
            catch
            {
                return false;
            }
        }

        public static void Set(bool enabled)
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunPath))
            {
                if (key == null) return;
                if (enabled) key.SetValue(ValueName, Command);
                else if (key.GetValue(ValueName) != null) key.DeleteValue(ValueName, false);
            }
        }
    }
}
