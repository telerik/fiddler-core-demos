# Sample apps for Progress® Telerik® FiddlerCore Embedded Engine

[FiddlerCore](https://www.telerik.com/fiddler/fiddlercore) is a cross-platform .NET library by Progress Telerik which allows capture 
and modification of HTTP/HTTPS traffic. Some of the most popular applications using FiddlerCore are 
[Telerik Fiddler](https://www.telerik.com/fiddler) (.NET Framework-based and running on Windows) and 
[Fiddler Everywhere](https://www.telerik.com/fiddler-everywhere) (.NET Core-based and running on Windows, Mac, and Linux).

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

Each demo is provided as a C# solution in two different flavors:
- .NET Core-based application targeting .NET Core 2.1 and using FiddlerCore for .NET Standard 2 (netstandard2.0).
- .NET Framework-based application targeting .NET Framework 4 and using FiddlerCore for .NET Framework 4 (net40).

To build the application, you would need the corresponding [.NET Core SDK](https://dotnet.microsoft.com/download/dotnet-core/2.1) 
or [.NET Framework SDK](https://dotnet.microsoft.com/download/visual-studio-sdks).

The APIs used are not so specific, so retargeting the sample applications, for example to .NET Core 3.0 or .NET Framework 4.8, 
is possible.

FiddlerCore-related NuGet packages are referenced from the Telerik NuGet server. When prompted for credentials during NuGet 
packages restore, use your [Telerik account](https://www.telerik.com/account) through you've obtained FiddlerCore.

## Contribution

Pull requests are welcome! Let's make these samples more understandable for everyone.
