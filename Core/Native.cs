using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SecHUD
{
    /// <summary>The two Windows API calls the scanner needs that .NET has no wrapper for.</summary>
    internal static class Native
    {
        /// <summary>Asks the network "who has this IP?" and returns the MAC address that answers.</summary>
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        internal static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physAddrLen);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort,
            int ipVersion, int tableClass, uint reserved);

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
