/*
* This demo program shows how to use the FiddlerCore library with an API server.
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using Fiddler;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text.Json;
using System.Threading.Tasks;

namespace CaptureTrafficAPI
{
    internal static class Program
    {
        // NOTE: In the next line, you can pass 0 for the port (instead of 8877) to have FiddlerCore auto-select an available port
        private const ushort fiddlerCoreListenPort = 8877;
        private const int apiServerPort = 8001;

        private static readonly ICollection<Session> sessions = new List<Session>();
        private static readonly ReaderWriterLockSlim sessionsLock = new ReaderWriterLockSlim();
        private static readonly object fiddlerLock = new object();

        private static readonly string assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        private static bool isFiddlerStarted = false;

        private static void Main()
        {
            AttachEventListeners();
            EnsureRootCertificate();
            StartAPIServer();
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

                Console.WriteLine($"Session list contains: {sessionsCount} sessions");
            };

            // Tell the system console to handle CTRL+C by calling our method that
            // gracefully shuts down the FiddlerCore.
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

        private static void StartAPIServer()
        {
            var builder = WebApplication.CreateBuilder();
            builder.Services.AddCors();
            
            var app = builder.Build();
            
            app.UseCors(builder => builder
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());

            // API Routes
            app.MapPost("/api/proxy/start", StartProxy);
            app.MapPost("/api/proxy/stop", StopProxy);
            app.MapGet("/api/proxy/status", GetProxyStatus);
            app.MapGet("/api/sessions", GetSessions);
            app.MapPost("/api/sessions/clear", ClearSessions);
            app.MapPost("/api/sessions/save", SaveSessions);
            app.MapGet("/", GetRoot);

            Console.WriteLine($"API Server starting on http://localhost:{apiServerPort}");
            Console.WriteLine("Available endpoints:");
            Console.WriteLine("  POST /api/proxy/start - Start the FiddlerCore proxy");
            Console.WriteLine("  POST /api/proxy/stop - Stop the FiddlerCore proxy");
            Console.WriteLine("  GET /api/proxy/status - Get proxy status");
            Console.WriteLine("  GET /api/sessions - Get captured sessions");
            Console.WriteLine("  POST /api/sessions/clear - Clear captured sessions");
            Console.WriteLine("  POST /api/sessions/save - Save sessions to SAZ file");

            app.Run($"http://localhost:{apiServerPort}");
        }

        private static object GetRoot(HttpContext context)
        {
            Console.WriteLine("Root endpoint called");
            var response = new
            {
                message = "CaptureTrafficAPI Server",
                endpoints = new[]
                {
                    "POST /api/proxy/start - Start the FiddlerCore proxy",
                    "POST /api/proxy/stop - Stop the FiddlerCore proxy",
                    "GET /api/proxy/status - Get proxy status",
                    "GET /api/sessions - Get captured sessions",
                    "POST /api/sessions/clear - Clear captured sessions",
                    "POST /api/sessions/save - Save sessions to SAZ file"
                }
            };

            Console.WriteLine($"Returning root response");
            return response;
        }

        private static object StartProxy(HttpContext context)
        {
            try
            {
                lock (fiddlerLock)
                {
                    if (isFiddlerStarted)
                    {
                        return new { error = "Proxy is already started" };
                    }

                    FiddlerCoreStartupSettings startupSettings =
                        new FiddlerCoreStartupSettingsBuilder()
                            .ListenOnPort(fiddlerCoreListenPort)
                            .RegisterAsSystemProxy()
                            .ChainToUpstreamGateway()
                            .DecryptSSL()
                            .EnableHTTP2()
                            .Build();

                    FiddlerApplication.Startup(startupSettings);
                    isFiddlerStarted = true;

                    FiddlerApplication.Log.LogString($"Created endpoint listening on port {CONFIG.ListenPort}");
                }

                return new { message = "Proxy started successfully", port = fiddlerCoreListenPort };
            }
            catch (Exception ex)
            {
                return new { error = $"Failed to start proxy: {ex.Message}" };
            }
        }

        private static object StopProxy(HttpContext context)
        {
            try
            {
                lock (fiddlerLock)
                {
                    if (!isFiddlerStarted)
                    {
                        return new { error = "Proxy is not running" };
                    }

                    FiddlerApplication.Shutdown();
                    isFiddlerStarted = false;
                }

                return new { message = "Proxy stopped successfully" };
            }
            catch (Exception ex)
            {
                return new { error = $"Failed to stop proxy: {ex.Message}" };
            }
        }

        private static object GetProxyStatus(HttpContext context)
        {
            Console.WriteLine("GetProxyStatus endpoint called");
            lock (fiddlerLock)
            {
                var result = new 
                { 
                    isRunning = isFiddlerStarted,
                    port = isFiddlerStarted ? fiddlerCoreListenPort : (int?)null,
                    sessionCount = GetSessionCount()
                };
                Console.WriteLine($"Returning status: {System.Text.Json.JsonSerializer.Serialize(result)}");
                return result;
            }
        }

        private static object GetSessions(HttpContext context)
        {
            try
            {
                var sessionList = new List<object>();
                
                sessionsLock.EnterReadLock();
                try
                {
                    foreach (Session s in sessions)
                    {
                        sessionList.Add(new
                        {
                            id = s.id,
                            method = s.oRequest.headers.HTTPMethod,
                            url = s.fullUrl,
                            responseCode = s.responseCode,
                            mimeType = s.oResponse?.MIMEType ?? "unknown"
                        });
                    }
                }
                finally
                {
                    sessionsLock.ExitReadLock();
                }

                return new { sessions = sessionList, count = sessionList.Count };
            }
            catch (Exception ex)
            {
                return new { error = $"Failed to get sessions: {ex.Message}" };
            }
        }

        private static object ClearSessions(HttpContext context)
        {
            try
            {
                sessionsLock.EnterWriteLock();
                try
                {
                    sessions.Clear();
                }
                finally
                {
                    sessionsLock.ExitWriteLock();
                }

                return new { message = "Sessions cleared successfully" };
            }
            catch (Exception ex)
            {
                return new { error = $"Failed to clear sessions: {ex.Message}" };
            }
        }

        private static object SaveSessions(HttpContext context)
        {
            try
            {
                string filename = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) +
                    Path.DirectorySeparatorChar + DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") + ".saz";

                bool success;
                int sessionCount;
                
                sessionsLock.EnterReadLock();
                try
                {
                    sessionCount = sessions.Count;
                    if (sessionCount > 0)
                    {
                        success = Utilities.WriteSessionArchive(filename, sessions.ToArray(), null);
                    }
                    else
                    {
                        return new { error = "No sessions to save" };
                    }
                }
                finally
                {
                    sessionsLock.ExitReadLock();
                }

                if (success)
                {
                    return new { message = "Sessions saved successfully", filename = filename, sessionCount = sessionCount };
                }
                else
                {
                    return new { error = "Failed to save sessions" };
                }
            }
            catch (Exception ex)
            {
                return new { error = $"Failed to save sessions: {ex.Message}" };
            }
        }

        private static int GetSessionCount()
        {
            try
            {
                sessionsLock.EnterReadLock();
                return sessions.Count;
            }
            finally
            {
                sessionsLock.ExitReadLock();
            }
        }

        private static void Quit()
        {
            Console.WriteLine("Shutting down...");

            lock (fiddlerLock)
            {
                if (isFiddlerStarted)
                {
                    FiddlerApplication.Shutdown();
                    isFiddlerStarted = false;
                }
            }

            Environment.Exit(0);
        }
    }
}
