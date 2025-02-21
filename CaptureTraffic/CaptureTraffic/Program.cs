/*
* This demo program shows how to use the FiddlerCore library.
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using Fiddler;

namespace CaptureTraffic
{
    internal static class Program
    {
        // NOTE: In the next line, you can pass 0 for the port (instead of 8877) to have FiddlerCore auto-select an available port
        private const ushort fiddlerCoreListenPort = 8877;

        private static readonly ICollection<Session> sessions = new List<Session>();
        private static readonly ReaderWriterLockSlim sessionsLock = new ReaderWriterLockSlim();

        private static readonly string assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        private static void Main()
        {
            AttachEventListeners();

            EnsureRootCertificate();

            StartupFiddlerCore();

            ExecuteUserCommands();

            Quit();
        }

        private static void AttachEventListeners()
        {
            //
            // It is important to understand that FiddlerCore calls event handlers on session-handling
            // background threads.  If you need to properly synchronize to the UI-thread (say, because
            // you're adding the sessions to a list view) you must call .Invoke on a delegate on the 
            // window handle.
            // 
            // If you are writing to a non-threadsafe data structure (e.g. List<T>) you must
            // use a Monitor or other mechanism to ensure safety.
            //

            FiddlerApplication.Log.OnLogString += (o, lea) => Console.WriteLine($"** LogString: {lea.LogString}");

            FiddlerApplication.BeforeRequest += session =>
            {
                // In order to enable response tampering, buffering mode MUST
                // be enabled; this allows FiddlerCore to permit modification of
                // the response in the BeforeResponse handler rather than streaming
                // the response to the client as the response comes in.
                session.bBufferResponse = false;

                // Set this property if you want FiddlerCore to automatically authenticate by
                // answering Digest/Negotiate/NTLM/Kerberos challenges itself
                // session["X-AutoAuth"] = "(default)";

                try
                {
                    sessionsLock.EnterWriteLock();
                    sessions.Add(session);
                }
                finally
                {
                    sessionsLock.ExitWriteLock();
                }
            };

            /*
            // The following event allows you to examine every response buffer read by Fiddler. Note that this isn't useful for the vast majority of
            // applications because the raw buffer is nearly useless; it's not decompressed, it includes both headers and body bytes, etc.
            //
            // This event is only useful for a handful of applications which need access to a raw, unprocessed byte-stream
            Fiddler.FiddlerApplication.OnReadResponseBuffer += (o, rrea) =>
            {
                // NOTE: arrDataBuffer is a fixed-size array. Only bytes 0 to iCountOfBytes should be read/manipulated.
                //
                // Just for kicks, lowercase every byte. Note that this will obviously break any binary content.
                for (int i = 0; i < e.iCountOfBytes; i++)
                {
                    if ((e.arrDataBuffer[i] > 0x40) && (e.arrDataBuffer[i] < 0x5b))
                    {
                        e.arrDataBuffer[i] = (byte)(e.arrDataBuffer[i] + (byte)0x20);
                    }
                }
                Console.WriteLine(String.Format("Read {0} response bytes for session {1}", e.iCountOfBytes, e.sessionOwner.id));
            }
            */

            /*
            Fiddler.FiddlerApplication.BeforeResponse += session => {
                // Console.WriteLine($"{session.id}:HTTP {session.responseCode} for {session.fullUrl}");

                // Uncomment the following two statements to decompress/unchunk the
                // HTTP response and subsequently modify any HTTP responses to replace 
                // instances of the word "Telerik" with "Progress". You MUST also
                // set session.bBufferResponse = true inside the BeforeRequest event handler above.
                //
                //session.utilDecodeResponse(); session.utilReplaceInResponse("Telerik", "Progress");
            };*/

            FiddlerApplication.AfterSessionComplete += session =>
            {
                //Console.WriteLine($"Finished session: {oS.fullUrl}");

                int sessionsCount = 0;
                try
                {
                    sessionsLock.EnterReadLock();
                    sessionsCount = sessions.Count;
                }
                finally
                {
                    sessionsLock.ExitReadLock();
                }

                if (sessionsCount == 0)
                    return;

                Console.Title = $"Session list contains: {sessionsCount} sessions";
            };

            // Tell the system console to handle CTRL+C by calling our method that
            // gracefully shuts down the FiddlerCore.
            //
            // Note, this doesn't handle the case where the user closes the window with the close button.
            Console.CancelKeyPress += (o, ccea) =>
            {
                Quit();
            };
        }

        private static void EnsureRootCertificate()
        {
            BCCertMaker.BCCertMaker certProvider = new BCCertMaker.BCCertMaker();
            CertMaker.oCertProvider = certProvider;

            // On first run generate root certificate using the loaded provider, then re-use it for subsequent runs.
            string rootCertificatePath = Path.Combine(assemblyDirectory, "..", "..", "RootCertificate.p12");
            string rootCertificatePassword = "S0m3T0pS3cr3tP4ssw0rd";
            if (!File.Exists(rootCertificatePath))
            {
                certProvider.CreateRootCertificate();
                certProvider.WriteRootCertificateAndPrivateKeyToPkcs12File(rootCertificatePath, rootCertificatePassword);
            }
            else
            {
                certProvider.ReadRootCertificateAndPrivateKeyFromPkcs12File(rootCertificatePath, rootCertificatePassword);
            }

            // Once the root certificate is set up, ensure it's trusted.
            if (!CertMaker.IsRootCertificateTrusted())
            {
                CertMaker.TrustRootCertificate();
            }
        }

        private static void StartupFiddlerCore()
        {
            FiddlerCoreStartupSettings startupSettings =
                new FiddlerCoreStartupSettingsBuilder()
                    .ListenOnPort(fiddlerCoreListenPort)
                    .RegisterAsSystemProxy()
                    .ChainToUpstreamGateway()
                    .DecryptSSL()
                    .EnableHTTP2()
                    .Build();

            FiddlerApplication.Startup(startupSettings);

            FiddlerApplication.Log.LogString($"Created endpoint listening on port {CONFIG.ListenPort}");
        }

        private static void ExecuteUserCommands()
        {
            bool done = false;
            do
            {
                Console.WriteLine("Enter a command [C=Clear; L=List; W=write SAZ; R=read SAZ; Q=Quit]:");
                Console.Write(">");
                ConsoleKeyInfo cki = Console.ReadKey();
                Console.WriteLine();
                switch (char.ToLower(cki.KeyChar))
                {
                    case 'c':
                        try
                        {
                            sessionsLock.EnterWriteLock();
                            sessions.Clear();
                        }
                        finally
                        {
                            sessionsLock.ExitWriteLock();
                        }

                        Console.Title = $"Session list contains: 0 sessions";

                        WriteCommandResponse("Clear...");
                        FiddlerApplication.Log.LogString("Cleared session list.");
                        break;

                    case 'l':
                        WriteSessions(sessions);
                        break;

                    case 'w':
                        string password = null;
                        Console.WriteLine("Password Protect this Archive (Y/N)?");
                        ConsoleKeyInfo yesNo = Console.ReadKey();
                        if ((yesNo.KeyChar == 'y') || (yesNo.KeyChar == 'Y'))
                        {
                            Console.WriteLine($"{Environment.NewLine}Enter the password:");
                            password = Console.ReadLine();
                        }

                        Console.WriteLine();

                        SaveSessionsToDesktop(sessions, password);
                        break;

                    case 'r':
                        ReadSessions(sessions);

                        int sessionsCount;
                        try
                        {
                            sessionsLock.EnterReadLock();
                            sessionsCount = sessions.Count;
                        }
                        finally
                        {
                            sessionsLock.ExitReadLock();
                        }

                        Console.Title = $"Session list contains: {sessionsCount} sessions";

                        break;

                    case 'q':
                        done = true;
                        break;
                }
            } while (!done);
        }

        private static void Quit()
        {
            WriteCommandResponse("Shutting down...");

            FiddlerApplication.Shutdown();
        }

        private static void SaveSessionsToDesktop(IEnumerable<Session> sessions, string password)
        {
            string filename = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) +
                Path.DirectorySeparatorChar + DateTime.Now.ToString("hh-mm-ss") + ".saz";

            string response;
            try
            {
                sessionsLock.EnterReadLock();
                if (sessions.Any())
                {
                    bool success = Utilities.WriteSessionArchive(filename, sessions.ToArray(), password);
                    response = $"{(success ? "Wrote" : "Failed to save")}: {filename}";
                }
                else
                {
                    response = "No sessions have been captured.";
                }
            }
            catch (Exception ex)
            {
                response = $"Save failed: {ex.Message}";
            }
            finally
            {
                sessionsLock.ExitReadLock();
            }

            WriteCommandResponse(response);
        }

        private static void ReadSessions(ICollection<Session> sessions)
        {
            string sazFilename = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + Path.DirectorySeparatorChar + "ToLoad.saz";

            Session[] loaded = Utilities.ReadSessionArchive(sazFilename, "", (file, part) =>
            {
                Console.WriteLine($"Enter the password for { part } (or just hit Enter to cancel):");
                string sResult = Console.ReadLine();
                Console.WriteLine();
                return sResult;
            }, out string sazVersion);

            if (loaded == null || loaded.Length == 0)
            {
                WriteCommandResponse($"Could not load sessions from {sazFilename}");
                return;
            }

            try
            {
                sessionsLock.EnterWriteLock();
                for (int i = 0; i < loaded.Length; i++)
                {
                    sessions.Add(loaded[i]);
                }
            }
            finally
            {
                sessionsLock.ExitWriteLock();
            }

            WriteCommandResponse($"Loaded: {loaded.Length} sessions.");
        }

        private static void WriteCommandResponse(string s)
        {
            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(s);
            Console.ForegroundColor = oldColor;
        }

        private static void WriteSessions(IEnumerable<Session> sessions)
        {
            ConsoleColor oldColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.White;
            StringBuilder sb = new StringBuilder($"Session list contains:{Environment.NewLine}");
            try
            {
                sessionsLock.EnterReadLock();
                foreach (Session s in sessions)
                {
                    sb.AppendLine($"{s.id} {s.oRequest.headers.HTTPMethod} {Ellipsize(s.fullUrl, 60)}");
                    sb.AppendLine($"{s.responseCode} {s.oResponse.MIMEType}{Environment.NewLine}");
                }
            }
            finally
            {
                sessionsLock.ExitReadLock();
            }

            Console.Write(sb.ToString());
            Console.ForegroundColor = oldColor;
        }

        private static string Ellipsize(string text, int length)
        {
            if (Equals(text, null)) throw new ArgumentNullException(nameof(text));

            const int minLength = 3;

            if (length < minLength) throw new ArgumentOutOfRangeException(nameof(length), $"{nameof(length)} cannot be less than {minLength}");

            if (text.Length <= length) return text;

            return text.Substring(0, length - minLength) + new string('.', minLength);
        }
    }
}

