using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecHUD
{
    /// <summary>The few Windows API calls the app needs that .NET has no wrapper for.</summary>
    internal static class Native
    {
        /// <summary>Asks the network "who has this IP?" and returns the MAC address that answers.</summary>
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        internal static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physAddrLen);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort,
            int ipVersion, int tableClass, uint reserved);

        // ---- live watch ----

        internal const int RegNotifyChangeName = 0x1;
        internal const int RegNotifyChangeLastSet = 0x4;

        /// <summary>Signals the event the next time the registry key changes. It fires once, then has to be asked again.</summary>
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern int RegNotifyChangeKeyValue(SafeRegistryHandle key,
            [MarshalAs(UnmanagedType.Bool)] bool watchSubtree, int notifyFilter,
            SafeWaitHandle notifyEvent, [MarshalAs(UnmanagedType.Bool)] bool asynchronous);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserEnum(string server, int level, int filter, out IntPtr buffer,
            int preferredLength, out int entriesRead, out int totalEntries, ref int resumeHandle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buffer,
            int preferredLength, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        /// <summary>
        /// A cheap list of the local account names plus the members of one local group. The live
        /// watch asks for this every couple of seconds, which is far lighter than a WMI query.
        /// Returns null when Windows will not answer, so the caller can fall back.
        /// </summary>
        internal static List<string> QuickAccountList(string adminGroupName)
        {
            const int filterNormalAccount = 2;
            const int maxPreferredLength = -1;
            var names = new List<string>();

            IntPtr buffer = IntPtr.Zero;
            try
            {
                int read, total, resume = 0;
                int status = NetUserEnum(null, 0, filterNormalAccount, out buffer, maxPreferredLength, out read, out total, ref resume);
                if (status != 0 || buffer == IntPtr.Zero) return null;
                for (int i = 0; i < read; i++)
                {
                    IntPtr text = Marshal.ReadIntPtr(buffer, i * IntPtr.Size); // USER_INFO_0: one string pointer
                    string name = text == IntPtr.Zero ? null : Marshal.PtrToStringUni(text);
                    if (!string.IsNullOrEmpty(name)) names.Add("user|" + name);
                }
            }
            catch
            {
                return null;
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }

            if (string.IsNullOrEmpty(adminGroupName)) return names;
            buffer = IntPtr.Zero;
            try
            {
                int read, total;
                IntPtr resume = IntPtr.Zero; // pointer-sized for this call, unlike NetUserEnum
                int status = NetLocalGroupGetMembers(null, adminGroupName, 3, out buffer, maxPreferredLength, out read, out total, ref resume);
                if (status == 0 && buffer != IntPtr.Zero)
                {
                    for (int i = 0; i < read; i++)
                    {
                        IntPtr text = Marshal.ReadIntPtr(buffer, i * IntPtr.Size); // LOCALGROUP_MEMBERS_INFO_3: one string pointer
                        string name = text == IntPtr.Zero ? null : Marshal.PtrToStringUni(text);
                        if (!string.IsNullOrEmpty(name)) names.Add("admin|" + name);
                    }
                }
            }
            catch
            {
                // The user list alone is still a useful signal.
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
            return names;
        }

        // ---- file signatures ----

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WinTrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CatalogInfo
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WinTrustData data);

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem,
            [MarshalAs(UnmanagedType.LPWStr)] string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, SafeFileHandle file,
            ref uint hashSize, [Out] byte[] hash, uint flags);

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize,
            uint flags, IntPtr previous);

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CatalogInfo info, uint flags);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

        /// <summary>
        /// Asks Windows whether the signature inside a file is valid and trusted. Returns 0 for
        /// yes, otherwise the Windows error code. No window is shown and nothing is fetched from
        /// the internet: revocation is checked from what this PC already has cached.
        /// </summary>
        internal static int VerifyFileSignature(string path)
        {
            const uint uiNone = 2, revokeNone = 0, choiceFile = 1, stateIgnore = 0;
            const uint cacheOnlyUrlRetrieval = 0x1000;
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // the standard "is this file signed" check

            var file = new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)), pcwszFilePath = path };
            IntPtr filePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
            try
            {
                Marshal.StructureToPtr(file, filePointer, false);
                var data = new WinTrustData
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData)),
                    dwUIChoice = uiNone,
                    fdwRevocationChecks = revokeNone,
                    dwUnionChoice = choiceFile,
                    pFile = filePointer,
                    dwStateAction = stateIgnore,
                    dwProvFlags = cacheOnlyUrlRetrieval
                };
                return WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            }
            finally
            {
                Marshal.DestroyStructure(filePointer, typeof(WinTrustFileInfo));
                Marshal.FreeHGlobal(filePointer);
            }
        }

        /// <summary>The catalog file that vouches for this file, or null when no installed catalog lists it.</summary>
        internal static string FindCatalogFor(string path)
        {
            foreach (string algorithm in new[] { "SHA256", null }) // null = the older SHA-1 catalogs
            {
                IntPtr admin;
                try
                {
                    if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
                }
                catch
                {
                    return null;
                }
                try
                {
                    using (var stream = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read,
                        System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete))
                    {
                        uint size = 0;
                        CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, null, 0);
                        if (size == 0 || size > 128) continue;
                        var hash = new byte[size];
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref size, hash, 0)) continue;

                        IntPtr catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                        if (catalog == IntPtr.Zero) continue;
                        try
                        {
                            var info = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf(typeof(CatalogInfo)) };
                            if (CryptCATCatalogInfoFromContext(catalog, ref info, 0) && !string.IsNullOrEmpty(info.wszCatalogFile))
                                return info.wszCatalogFile;
                        }
                        finally
                        {
                            CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                        }
                    }
                }
                catch
                {
                    // A file that cannot be opened simply has no answer.
                }
                finally
                {
                    CryptCATAdminReleaseContext(admin, 0);
                }
            }
            return null;
        }

        // ---- which program is that ----

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, System.Text.StringBuilder name, ref uint size);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>The full path of a running program, or "" when Windows will not say (a protected system process).</summary>
        internal static string GetProcessPath(int processId)
        {
            const uint queryLimitedInformation = 0x1000; // the least access there is, enough for the path
            IntPtr handle = IntPtr.Zero;
            try
            {
                handle = OpenProcess(queryLimitedInformation, false, processId);
                if (handle == IntPtr.Zero) return "";
                var name = new System.Text.StringBuilder(1024);
                uint size = (uint)name.Capacity;
                return QueryFullProcessImageName(handle, 0, name, ref size) ? name.ToString(0, (int)size) : "";
            }
            catch
            {
                return "";
            }
            finally
            {
                if (handle != IntPtr.Zero) CloseHandle(handle);
            }
        }

        private const int AfInet = 2;
        private const int TcpTableOwnerPidListener = 3;

        /// <summary>Maps each listening IPv4 TCP port to the process id that owns it.</summary>
        internal static Dictionary<int, int> GetListenerPids()
        {
            var map = new Dictionary<int, int>();
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidListener, 0);
                if (size <= 0) return map;

                size += 4096; // headroom in case a listener appears between the two calls
                buffer = Marshal.AllocHGlobal(size);
                if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidListener, 0) != 0) return map;

                // MIB_TCPTABLE_OWNER_PID: a DWORD count, then rows of six DWORDs
                // (state, localAddr, localPort, remoteAddr, remotePort, owningPid).
                int count = Marshal.ReadInt32(buffer);
                const int rowSize = 24;
                for (int i = 0; i < count; i++)
                {
                    int offset = 4 + i * rowSize;
                    if (offset + rowSize > size) break;
                    int rawPort = Marshal.ReadInt32(buffer, offset + 8);
                    int pid = Marshal.ReadInt32(buffer, offset + 20);
                    int port = ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF); // network byte order
                    map[port] = pid;
                }
            }
            catch
            {
                // Process names are a nice-to-have. The port list itself comes from .NET.
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
            return map;
        }
    }
}
