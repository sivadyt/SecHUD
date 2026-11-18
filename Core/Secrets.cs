using System;
using System.Security.Cryptography;
using System.Text;

namespace SecHUD
{
    /// <summary>
    /// Keeps the Proxmox token and the Discord webhook out of plain text. Values are encrypted with
    /// Windows DPAPI under the current user account, so the config file is useless on another
    /// account or another PC.
    /// </summary>
    public static class Secrets
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SecHUD.secrets.v1");

        public static string Protect(string plain)
        {
            if (string.IsNullOrEmpty(plain)) return "";
            byte[] sealedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), Entropy, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(sealedBytes);
        }

        public static string Unprotect(string stored)
        {
            if (string.IsNullOrEmpty(stored)) return "";
            try
            {
                byte[] plain = ProtectedData.Unprotect(Convert.FromBase64String(stored), Entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plain);
            }
            catch
            {
                return ""; // copied from another account or edited by hand
            }
        }
    }
}
