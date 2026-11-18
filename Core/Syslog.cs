using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SecHUD
{
    /// <summary>
    /// A small syslog receiver (UDP). Point a Linux box at this PC and its logs show up in the
    /// Logs tab. Off by default; it only listens when turned on in Settings.
    /// </summary>
    public class SyslogServer : IDisposable
    {
        private UdpClient client;
        private Thread thread;
        private volatile bool running;

        /// <summary>Raised on a background thread for every message.</summary>
        public event Action<SyslogMessage> Received;

        public int Port { get; private set; }
        public bool IsRunning { get { return running; } }

        public bool Start(int port, out string error)
        {
            return Start(port, false, out error);
        }

        /// <summary>loopbackOnly listens on 127.0.0.1 only, which the tests use so no firewall prompt appears.</summary>
        public bool Start(int port, bool loopbackOnly, out string error)
        {
            Stop();
            error = "";
            try
            {
                client = new UdpClient(new IPEndPoint(loopbackOnly ? IPAddress.Loopback : IPAddress.Any, port));
                Port = port;
                running = true;
                thread = new Thread(Listen) { IsBackground = true, Name = "SecHUD syslog" };
                thread.Start();
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                running = false;
                client = null;
                return false;
            }
        }

        public void Stop()
        {
            running = false;
            UdpClient old = client;
            client = null;
            if (old != null)
            {
                try { old.Close(); } catch { }
            }
        }

        public void Dispose()
        {
            Stop();
        }

        private void Listen()
        {
            UdpClient socket = client;
            while (running && socket != null)
            {
                try
                {
                    var remote = new IPEndPoint(IPAddress.Any, 0);
                    byte[] data = socket.Receive(ref remote);
                    SyslogMessage message = Parse(data, remote.Address.ToString(), DateTime.Now);
                    Action<SyslogMessage> handler = Received;
                    if (handler != null && message != null) handler(message);
                }
                catch (SocketException)
                {
                    if (!running) break; // socket closed by Stop
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch
                {
                }
            }
        }

        /// <summary>Reads the classic "&lt;PRI&gt;text" layout. Anything else is kept as plain text.</summary>
        public static SyslogMessage Parse(byte[] data, string source, DateTime now)
        {
            if (data == null || data.Length == 0) return null;
            string text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 4096));
            int severity = 6; // informational

            if (text.Length > 2 && text[0] == '<')
            {
                int close = text.IndexOf('>');
                int priority;
                if (close > 1 && close <= 4 && int.TryParse(text.Substring(1, close - 1), out priority))
                {
                    severity = priority & 7;
                    text = text.Substring(close + 1);
                }
            }

            var clean = new StringBuilder(text.Length);
            foreach (char c in text)
            {
                clean.Append(char.IsControl(c) ? ' ' : c);
            }
            text = clean.ToString().Trim();
            if (text.Length == 0) return null;
            if (text.Length > 1000) text = text.Substring(0, 1000);

            return new SyslogMessage { Time = now, Source = source, Severity = severity, Text = text };
        }
    }

    /// <summary>Watches incoming syslog lines for repeated login failures (password guessing).</summary>
    public class SyslogAuthRule
    {
        private static readonly string[] Signs = { "authentication failure", "failed password", "invalid user", "failed login" };
        private readonly Dictionary<string, List<DateTime>> failures = new Dictionary<string, List<DateTime>>();
        private readonly Dictionary<string, DateTime> lastAlert = new Dictionary<string, DateTime>();

        public int Threshold { get; set; }
        public TimeSpan Window { get; set; }

        public SyslogAuthRule()
        {
            Threshold = 5;
            Window = TimeSpan.FromMinutes(10);
        }

        public static bool IsAuthFailure(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            string lower = text.ToLowerInvariant();
            return Signs.Any(s => lower.Contains(s));
        }

        /// <summary>Returns an event when a source crosses the threshold, at most once per window per source.</summary>
        public EventEntry Check(SyslogMessage message)
        {
            if (message == null || !IsAuthFailure(message.Text)) return null;
            lock (failures)
            {
                List<DateTime> times;
                if (!failures.TryGetValue(message.Source, out times))
                {
                    times = new List<DateTime>();
                    failures[message.Source] = times;
                }
                times.Add(message.Time);
                times.RemoveAll(t => message.Time - t > Window);
                if (times.Count < Threshold) return null;

                DateTime last;
                if (lastAlert.TryGetValue(message.Source, out last) && message.Time - last < Window) return null;
                lastAlert[message.Source] = message.Time;

                return new EventEntry
                {
                    Ts = message.Time.ToString("s"),
                    Type = "syslog",
                    Severity = "high",
                    Technique = "T1110",
                    Msg = times.Count + " failed logins reported by " + message.Source + " in " + (int)Window.TotalMinutes + " min"
                };
            }
        }
    }
}
