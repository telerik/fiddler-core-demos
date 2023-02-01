using Fiddler;
using System.Reflection;

namespace MauiAppFiddlerCore;

public partial class App : Application
{

    public int capturedSessionsCount = 0;

    private const ushort fiddlerCoreListenPort = 8877;

    private static readonly ICollection<Session> sessions = new List<Session>();
    private static readonly ReaderWriterLockSlim sessionsLock = new ReaderWriterLockSlim();

    private static readonly string assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

    public App()
	{

        AttachEventListeners();
        EnsureRootCertificate();
        StartupFiddlerCore();

        InitializeComponent();

		MainPage = new AppShell();
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


            //int sessionsCount = 0;
            try
            {
                sessionsLock.EnterReadLock();
                ((App)Application.Current).capturedSessionsCount++; // replace local varaible sessionsCount with mp.count
            }
            finally
            {
                sessionsLock.ExitReadLock();
            }

            if (((App)Application.Current).capturedSessionsCount == 0)
                return;

            // Console.Title = $"Session list contains: {sessionsCount} sessions";
        };

        // Tell the system console to handle CTRL+C by calling our method that
        // gracefully shuts down the FiddlerCore.
        //
        // Note, this doesn't handle the case where the user closes the window with the close button.
        //Console.CancelKeyPress += (o, ccea) =>
        //{
        //    Quit();
        //};
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
        if (!CertMaker.rootCertIsTrusted())
        {
            CertMaker.trustRootCert();
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
                .OptimizeThreadPool()
                .Build();

        FiddlerApplication.Startup(startupSettings);

        FiddlerApplication.Log.LogString($"Created endpoint listening on port {CONFIG.ListenPort}");
    }

    private static void Quit()
    {
        FiddlerApplication.Shutdown();
    }
}
