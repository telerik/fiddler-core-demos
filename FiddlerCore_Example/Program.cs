// See https://aka.ms/new-console-template for more information
using Fiddler;
using System.Collections.Concurrent;
using System.Text;

namespace FiddlerCore_Example
{
    class Program
    {
        // Use Thread safe collection to store the sessions.
        static ConcurrentQueue<Session> concurrentQueue = new ConcurrentQueue<Session>();

        static void Main(string[] args)
        {
            // Prepare FiddlerCore settings.
            FiddlerCoreStartupSettings startupSettings = new FiddlerCoreStartupSettingsBuilder()
                .DecryptSSL() // set it to capture HTTPS traffic as well (not only http)
                .RegisterAsSystemProxy() // tell FiddlerCore to act as system proxy
                .EnableHTTP2()
                .AllowRemoteClients()
                .Build();

            // Set the path to the certificate and its password.
            string rootCertificatePath = @"RootCertificate.p12";
            string rootCertificatePassword = "S0m3T0pS3cr3tP4ssw0rd";

            // Check if certificate exist.
            // If it doesn't, create one.
            if (!File.Exists(rootCertificatePath))
            {
                CertMaker.CreateRootCertificate();
                CertMaker.WriteRootCertificateAndPrivateKeyToPkcs12File(rootCertificatePath, rootCertificatePassword);
            }

            // Reuse the certificate every time when the app runs.
            CertMaker.ReadRootCertificateAndPrivateKeyFromPkcs12File(rootCertificatePath, rootCertificatePassword);

            // In case the current certificate is not already trusted, trust it, so we can capture HTTPS traffic.
            if (!CertMaker.IsRootCertificateTrusted())
            {
                var result = CertMaker.TrustRootCertificate();
                Console.WriteLine("Result of trusting certificate: " + result);
            }

            // Add event handles to act with the sessions.
            FiddlerApplication.BeforeRequest += FiddlerApplication_BeforeRequest;
            FiddlerApplication.AfterSessionComplete += FiddlerApplication_AfterSessionComplete;
            FiddlerApplication.ResponseHeadersAvailable += FiddlerApplication_ResponseHeadersAvailable;

            // Actually start FiddlerCore - this will set it as system proxy and start capturing traffic.
            FiddlerApplication.Startup(startupSettings);

            Console.WriteLine("\nSystem proxy is now set. Press Enter to remove the proxy and exit the application. Port: " + CONFIG.ListenPort);
            Console.ReadLine();

            FiddlerApplication.ResponseHeadersAvailable -= FiddlerApplication_ResponseHeadersAvailable;
            FiddlerApplication.BeforeRequest -= FiddlerApplication_BeforeRequest;
            FiddlerApplication.AfterSessionComplete -= FiddlerApplication_AfterSessionComplete;

            // Remove FiddlerCore as system proxy
            FiddlerApplication.Shutdown();

            // Store the collection of settings in a .saz file
            bool success = Utilities.WriteSessionArchive("sessions.saz", concurrentQueue.ToArray(), "password");
            Console.WriteLine("Saz file written? " + success);
        }

        private static void FiddlerApplication_BeforeRequest(Session oSession)
        {
            // The x-no-decrypt flag makes sense to be set only on CONNECT sessions.
            // In this case we set it for all CONNECTS except the ones to example.com
            // So, in case you open example.com in your browser, FiddlerCore will capture the HTTPS traffic to it.
            // For all the rest of the requests you'll see only CONNECT tunnels.
            // In case you want to filter by process, you can use the oSession.LocalProcessID and check if it is from a process you want to captures
            //if (oSession.HTTPMethodIs("CONNECT") && !oSession.HostnameIs("yahoo.com"))
            //{
            //   // Console.WriteLine("Setting x-no-decrypt to session: " + oSession.RequestMethod + " " + oSession.fullUrl);
            //    oSession.oFlags["x-no-decrypt"] = "ignore decryption for this session";
            //}
        }

        private static void FiddlerApplication_ResponseHeadersAvailable(Session oSession)
        {
            // Set this to true, so in BeforeResponse you'll be able to modify the the body.
            // If the value is false (default one), the response that you'll work with in the BeforeResponse handler
            // will be just a copy. The original one will already be streamed to the client and all of your modifications
            // will not be visible there.
            oSession.bBufferResponse = true;
        }

        static int sessions = 0;
        private static void FiddlerApplication_AfterSessionComplete(Session oSession)
        {
            // Debug info for a captured session
            Console.WriteLine(Interlocked.Increment(ref sessions) + " " + (oSession.isHTTP2 ? "HTTP/2": "HTTP/1.1") + " " + oSession.url);

            concurrentQueue.Enqueue(oSession);
            if (oSession.HostnameIs("example.com"))
            {
                // For each captured session to example com, create additional custom one. Can be recognized by the custom header
                Session customSession = GenerateCustomSession();
                concurrentQueue.Enqueue(customSession);
            }
        }

        private static Session GenerateCustomSession()
        {
            // Custom-Header: SetFromFiddlerCore

            // You must follow the HTTP standard for session's content:
            // <METHOD> <URL> <HTTP VERSION>
            // <HEADERS>
            // <always empty line here>
            // <OPTIONAL BODY>
            var requestBytes = Encoding.ASCII.GetBytes(@"GET https://example.com/ HTTP/1.1
Host: example.com
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache
sec-ch-ua: ""Chromium"";v=""124"", ""Google Chrome"";v=""124"", ""Not-A.Brand"";v=""99""
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""Windows""
DNT: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9,bg;q=0.8
Custom-Header: SetFromFiddlerCore

");

            var responseBytes = Encoding.ASCII.GetBytes(@"HTTP/1.1 200 OK
Accept-Ranges: bytes
Age: 583972
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Tue, 14 May 2024 18:50:59 GMT
Etag: ""3147526947""
Expires: Tue, 21 May 2024 18:50:59 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECAcc (sed/5891)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 648
Custom-Header: SetFromFiddlerCore

<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset=""utf-8"" />
    <meta http-equiv=""Content-type"" content=""text/html; charset=utf-8"" />
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
    <style type=""text/css"">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, ""Segoe UI"", ""Open Sans"", ""Helvetica Neue"", Helvetica, Arial, sans-serif;

    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>
</head>

<body>
<div>
    <h1>Example Exampl</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href=""https://www.iana.org/domains/example"">More information...</a></p>
</div>
</body>
</html>
        ");
            var customSession = new Session(requestBytes, responseBytes);

            return customSession;
        }

    }
}
