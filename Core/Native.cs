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
