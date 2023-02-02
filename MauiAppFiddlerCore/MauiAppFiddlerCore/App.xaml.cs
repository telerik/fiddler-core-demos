using Fiddler;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;

namespace MauiAppFiddlerCore;

public partial class App : Application
{
    public int capturedSessionsCount = 0;
    
    private static List<Session> sessions = new List<Session>();

    public App()
    {
        initFiddler();

        InitializeComponent();

        MainPage = new AppShell();
    }


    private static void initFiddler()
    {

        FiddlerApplication.Prefs.SetBoolPref("fiddler.certmaker.bc.Debug", true);

        //// Uncomment below line if you need verbose logs from FiddlerCore
        // Fiddler.FiddlerApplication.Log.OnLogString += delegate (object sender, LogEventArgs oLEA) { Console.WriteLine("** LogString: " + oLEA.LogString); };

        // Force BouncyCastle as certificate provideer
        BCCertMaker.BCCertMaker certProvider = new BCCertMaker.BCCertMaker();
        CertMaker.oCertProvider = certProvider;

        FiddlerApplication.AfterSessionComplete += FiddlerApplication_AfterSessionComplete;
        FiddlerApplication.BeforeRequest += FiddlerApplication_BeforeRequest;

        // The code below will always create a new certificate and will trust it
        // Trusting the certificate requires user to enter their password in a native macOS prompt
        // If you want to do it only once for the app on this machine, you can store the .p12 file on a well-known place
        // Then use certProvider.ReadRootCertificateAndPrivateKeyFromPkcs12File(rootCertificatePath, rootCertificatePassword); to force the app to use this certificate.
        // After that get the sha1 of the certificate with certProvider.GetRootCertificate().GetCertHashString();
        // Then check with the bash command "security trust-settings-export <file path>" if the sha1 of the certificate is in the trusted certificates inside the exported XML file.
        if (!CertMaker.createRootCert())
        {
            //Console.WriteLine("Unable to create cert for FiddlerCore.");
            return;
        }

        TrustRootCertificate();

        FiddlerCoreStartupSettings startupSettings =
                                        new FiddlerCoreStartupSettingsBuilder()
                                            .ListenOnPort(0)
                                            .DecryptSSL()
                                            // .RegisterAsSystemProxy() // Don't use on macOS as it will not work as expected. Use SetSystemProxy method below for this purpose
                                            .Build();

        var activeAdapterName = GetActiveAdapterName();
        FiddlerApplication.Startup(startupSettings);

        var port = FiddlerApplication.oProxy.ListenPort;
        SetSystemProxy(activeAdapterName, "127.0.0.1", port);

        //Console.WriteLine("Proxy is now set, press enter to remove it");
        //Console.ReadLine();

        // Cleanup to ensure proxy is removed from OS settings
        //RemoveSystemProxy(activeAdapterName);
        //FiddlerApplication.Shutdown();

        bool success = Fiddler.Utilities.WriteSessionArchive("sessions.saz", sessions.ToArray(), "passwoRd");
        if (success)
        {
            //Console.WriteLine("Successfully written the sessions to file!");
        }
    }

    private static void FiddlerApplication_BeforeRequest(Session oSession)
    {
        // Console.WriteLine("Before executing requst for url: " + oSession.fullUrl);
    }


    private static void FiddlerApplication_AfterSessionComplete(Session oSession)
    {
        ((App)Application.Current).capturedSessionsCount++; // for demo purposes only

        sessions.Add(oSession);
    }


    private static void TrustRootCertificate()
    {
        CertMaker.EnsureReady();
        ICertificateProvider5 certificateProvider = (ICertificateProvider5)CertMaker.oCertProvider;

        // first export the certificate to a temp file, as the commands for import work with actual file
        string certificatePath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), System.IO.Path.GetRandomFileName());
        certificateProvider.WriteRootCertificateToDerEncodedFile(certificatePath);

        //Console.WriteLine("Certificate path: " + certificatePath);
        try
        {
            string shellScript = $@"

login_keychains_paths=$(security list-keychains | grep -e ""\Wlogin.keychain\W"");

if [ -z ""$login_keychains_paths"" ]
    then
        echo ""No login keychain found."";
        exit 10;
fi

security add-trusted-cert -k login.keychain ""{certificatePath}"";

security_exit_code=$?;

if [ $security_exit_code -ne 0 ]
    then
        echo ""security add-trusted-cert failed with error code $security_exit_code"";
        exit $security_exit_code;
fi".Replace("\"", "\\\"").Replace("\r\n", "\n");

            Process process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{shellScript}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };

            process.Start();
            process.WaitForExit();

            switch (process.ExitCode)
            {
                case 0:
                    return;
                case 10:
                    throw new System.Exception("Unable to find login.keychain. Please create one or import the certificate manually in your default keychain.");
                default:
                    throw new System.Exception("Unable to trust the root certificate. Try importing and trusting it manually.");
            }
        }
        finally
        {
            File.Delete(certificatePath);
        }
    }


    private static string GetActiveAdapterName()
    {
        var command = @"services=$(networksetup -listnetworkserviceorder | sed '1d;/(\*)/,+2d;s/^([^)]*) \(.*\)$/\1FIDDLER_SEPARATOR/g;s/^.*Device: \([^)]*\))/\1/g;/^$/d' | sed 'N;s/\n//')

while read line; do
    sname=$(echo ""$line"" | awk -F  ""FIDDLER_SEPARATOR"" '{print $1}')
    sdev=$(echo ""$line"" | awk -F  ""FIDDLER_SEPARATOR"" '{print $2}')
    if [ -n ""$sdev"" ]; then
        ifconfig ""$sdev"" 2>/dev/null | grep 'status: active' > /dev/null 2>&1
        rc=""$?""
        if [ ""$rc"" -eq 0 ]; then
            currentservice=""$sname""
            echo ""$currentservice""
            break
        fi
    fi
done <<< ""$(echo ""$services"")""

if ! [ -n ""$currentservice"" ]; then
    >&2 echo ""Could not find current service""
    >&2 echo ""$services""
    exit 1
fi";
        return ExecuteBash(command).Trim();
    }

    private static void SetSystemProxy(string networkInterfaceName, string proxyHost, int proxyPort)
    {
        var command = string.Format(@"networksetup -setwebproxy ""{0}"" '{1}' {2} off && 
networksetup -setwebproxystate ""{0}"" on && 
networksetup -setsecurewebproxy ""{0}"" '{1}' {2} off && 
networksetup -setsecurewebproxystate ""{0}"" on", networkInterfaceName, proxyHost, proxyPort);

        RunShellThroughOsascript(command, "prompt text");
    }

    private static void RemoveSystemProxy(string networkInterfaceName)
    {
        var command = string.Format(@"networksetup -setwebproxystate ""{0}"" off && 
networksetup -setsecurewebproxystate ""{0}"" off", networkInterfaceName);

        RunShellThroughOsascript(command, "prompt text");
    }

    private static void RunShellThroughOsascript(string script, string prompt)
    {
        // double escape the quotes (once for osascript and once for the bash it spawns) and ensure macOS line-endings as the scripts are always executed on macOS

        var escapedScript = script.Replace("\"", "\\\\\\\"").Replace("\r\n", "\n");
        var osascriptFilePath = "/usr/bin/osascript";
        Process process = new Process()
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = osascriptFilePath,
                Arguments = $"-e \"do shell script \\\"{escapedScript}\\\" with prompt \\\"{prompt}\\\"\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            }
        };

        process.Start();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new SystemException("Error when executing command " + script);
        }
    }

    private static readonly string startToken = "FIDDLER_SCRIPT_START";

    private static readonly string endToken = "FIDDLER_SCRIPT_END";

    public static string ExecuteBash(string cmd)
    {
        // escape the quotes for the bash script and ensure macOS line-endings as the scripts are always executed on macOS
        var escapedArgs = cmd.Replace("\"", "\\\"").Replace("\r\n", "\n");
        escapedArgs = "echo " + startToken + "\n" + escapedArgs + "\necho " + endToken + "\n";
        var process = new Process()
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c \"{escapedArgs}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            }
        };

        process.Start();
        string result = process.StandardOutput.ReadToEnd();
        string errors = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (!string.IsNullOrEmpty(result))
        {
            var startTokenIndex = result.IndexOf(startToken);
            if (startTokenIndex != -1)
            {
                result = result.Substring(startTokenIndex + startToken.Length);
            }

            var endTokenIndex = result.IndexOf(endToken);
            if (endTokenIndex != -1)
            {
                result = result.Substring(0, endTokenIndex);
            }
        }

        return result;
    }
}
