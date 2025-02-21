# Sample apps for Progress® Telerik® FiddlerCore Embedded Engine

[FiddlerCore](https://www.telerik.com/fiddlercore) is a cross-platform .NET library by Progress Telerik which allows capture
and modification of HTTP/HTTPS traffic. Some of the most popular applications using FiddlerCore are
[Telerik Fiddler](https://www.telerik.com/download/fiddler) (.NET Framework-based and running on Windows) and
[Fiddler Everywhere](https://www.telerik.com/fiddler) (.NET Core-based and running on Windows, Mac, and Linux).

This repository contains sample applications demonstrating possible usages of the FiddlerCore API.

## Demos description

Currently the following demo is provided:

### [Capture traffic](/CaptureTraffic)

The sample demonstrates the following concepts:

- Generate and install unique certificate that will be used for decrypting HTTPS traffic.
- Set proxy allowing to capture all traffic from the machine, and chaining to upstream proxy if needed. Reset the proxy on exit.
- Capture HTTP/S sessions and preserve them in a list.
- Save the sessions in a SAZ (Session Archive Zip) file, a standard archive file which can be password-protected and, if needed,
opened later with Fiddler.
- Open a SAZ file and list session information.

## Building a sample

If your application is targeting .NET Framework, you can find a demo for the old FiddlerCore version,
which supports NET Framework 4.8 (https://github.com/telerik/fiddler-core-demos/tree/v5.0.2)

.NET based application targeting .NET 8 and using FiddlerCore for .NET.

To build the application, you would need the corresponding [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0).

FiddlerCore-related NuGet packages are referenced from the Telerik NuGet server. When prompted for credentials during NuGet
packages restore, use your [Telerik account](https://www.telerik.com/account) through you've obtained FiddlerCore.

## Contribution

Pull requests are welcome! Let's make these samples more understandable for everyone.
