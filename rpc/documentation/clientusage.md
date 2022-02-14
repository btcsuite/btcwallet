# Client usage

Clients use RPC to interact with the wallet.  A client may be implemented in any
language directly supported by [gRPC](http://www.grpc.io/), languages capable of
performing [FFI](https://en.wikipedia.org/wiki/Foreign_function_interface) with
these, and languages that share a common runtime (e.g. Scala, Kotlin, and Ceylon
for the JVM, F# for the CLR, etc.).  Exact instructions differ slightly
depending on the language being used, but the general process is the same for
each.  In short summary, to call RPC server methods, a client must:

1. Generate client bindings specific for the [wallet RPC server API](./api.md)
2. Import or include the gRPC dependency
3. (Optional) Wrap the client bindings with application-specific types
4. Open a gRPC channel using the wallet server's self-signed TLS certificate

The only exception to these steps is if the client is being written in Go.  In
that case, the first step may be omitted by importing the bindings from
btcwallet itself.

The rest of this document provides short examples of how to quickly get started
by implementing a basic client that fetches the balance of the default account
(account 0) from a testnet3 wallet listening on `localhost:18332` in several
different languages:

- [Go](#go)
- [C++](#cpp)
- [C#](#csharp)
- [Node.js](#nodejs)
- [Python](#python)

Unless otherwise stated under the language example, it is assumed that
gRPC is already already installed.  The gRPC installation procedure
can vary greatly depending on the operating system being used and
whether a gRPC source install is required.  Follow the [gRPC install
instructions](https://github.com/grpc/grpc/blob/master/INSTALL) if
gRPC is not already installed.  A full gRPC install also includes
[Protocol Buffers](https://github.com/google/protobuf) (compiled with
support for the proto3 language version), which contains the protoc
tool and language plugins used to compile this project's `.proto`
files to language-specific bindings.

## Go

The native gRPC library (gRPC Core) is not required for Go clients (a
pure Go implementation is used instead) and no additional setup is
required to generate Go bindings.

```Go
package main

import (
	"fmt"
	"path/filepath"

	pb "github.com/btcsuite/btcwallet/rpc/walletrpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/btcsuite/btcd/btcutil"
)

var certificateFile = filepath.Join(btcutil.AppDataDir("btcwallet", false), "rpc.cert")

func main() {
	creds, err := credentials.NewClientTLSFromFile(certificateFile, "localhost")
	if err != nil {
		fmt.Println(err)
		return
	}
	conn, err := grpc.Dial("localhost:18332", grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	c := pb.NewWalletServiceClient(conn)

	balanceRequest := &pb.BalanceRequest{
		AccountNumber:         0,
		RequiredConfirmations: 1,
	}
	balanceResponse, err := c.Balance(context.Background(), balanceRequest)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Spendable balance: ", btcutil.Amount(balanceResponse.Spendable))
}
```

<a name="cpp"/>
## C++

**Note:** Protocol Buffers and gRPC require at least C++11.  The example client
is written using C++14.

**Note:** The following instructions assume the client is being written on a
Unix-like platform (with instructions using the `sh` shell and Unix-isms in the
example source code) with a source gRPC install in `/usr/local`.

First, generate the C++ language bindings by compiling the `.proto`:

```bash
$ protoc -I/path/to/btcwallet/rpc --cpp_out=. --grpc_out=. \
  --plugin=protoc-gen-grpc=$(which grpc_cpp_plugin) \
  /path/to/btcwallet/rpc/api.proto
```

Once the `.proto` file has been compiled, the example client can be completed.
Note that the following code uses synchronous calls which will block the main
thread on all gRPC IO.

```C++
// example.cc
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <grpc++/grpc++.h>

#include "api.grpc.pb.h"

using namespace std::string_literals;

struct NoHomeDirectoryException : std::exception {
    char const* what() const noexcept override {
        return "Failed to lookup home directory";
    }
};

auto read_file(std::string const& file_path) -> std::string {
    std::ifstream in{file_path};
    std::stringstream ss{};
    ss << in.rdbuf();
    return ss.str();
}

auto main() -> int {
    // Before the gRPC native library (gRPC Core) is lazily loaded and
    // initialized, an environment variable must be set so BoringSSL is
    // configured to use ECDSA TLS certificates (required by btcwallet).
    setenv("GRPC_SSL_CIPHER_SUITES", "HIGH+ECDSA", 1);

    // Note: This path is operating system-dependent.  This can be created
    // portably using boost::filesystem or the experimental filesystem class
    // expected to ship in C++17.
    auto wallet_tls_cert_file = []{
        auto pw = getpwuid(getuid());
        if (pw == nullptr || pw->pw_dir == nullptr) {
            throw NoHomeDirectoryException{};
        }
        return pw->pw_dir + "/.btcwallet/rpc.cert"s;
    }();

    grpc::SslCredentialsOptions cred_options{
        .pem_root_certs = read_file(wallet_tls_cert_file),
    };
    auto creds = grpc::SslCredentials(cred_options);
    auto channel = grpc::CreateChannel("localhost:18332", creds);
    auto stub = walletrpc::WalletService::NewStub(channel);

    grpc::ClientContext context{};

    walletrpc::BalanceRequest request{};
    request.set_account_number(0);
    request.set_required_confirmations(1);

    walletrpc::BalanceResponse response{};
    auto status = stub->Balance(&context, request, &response);
    if (!status.ok()) {
        std::cout << status.error_message() << std::endl;
    } else {
        std::cout << "Spendable balance: " << response.spendable() << " Satoshis" << std::endl;
    }
}
```

The example can then be built with the following commands:

```bash
$ c++ -std=c++14 -I/usr/local/include -pthread -c -o api.pb.o api.pb.cc
$ c++ -std=c++14 -I/usr/local/include -pthread -c -o api.grpc.pb.o api.grpc.pb.cc
$ c++ -std=c++14 -I/usr/local/include -pthread -c -o example.o example.cc
$ c++ *.o -L/usr/local/lib -lgrpc++ -lgrpc -lgpr -lprotobuf -lpthread -ldl -o example
```

<a name="csharp"/>
## C&#35;

The quickest way of generating client bindings in a Windows .NET environment is
by using the protoc binary included in the gRPC NuGet package.  From the NuGet
package manager PowerShell console, this can be performed with:

```
PM> Install-Package Grpc
```

The protoc and C# plugin binaries can then be found in the packages directory.
For example, `.\packages\Google.Protobuf.x.x.x\tools\protoc.exe` and
`.\packages\Grpc.Tools.x.x.x\tools\grpc_csharp_plugin.exe`.

When writing a client on other platforms (e.g. Mono on OS X), or when doing a
full gRPC source install on Windows, protoc and the C# plugin must be installed
by other means.  Consult the [official documentation](https://github.com/grpc/grpc/blob/master/src/csharp/README.md)
for these steps.

Once protoc and the C# plugin have been obtained, client bindings can be
generated.  The following command generates the files `Api.cs` and `ApiGrpc.cs`
in the `Example` project directory using the `Walletrpc` namespace:

```PowerShell
PS> & protoc.exe -I \Path\To\btcwallet\rpc --csharp_out=Example --grpc_out=Example `
    --plugin=protoc-gen-grpc=\Path\To\grpc_csharp_plugin.exe `
    \Path\To\btcwallet\rpc\api.proto
```

Once references have been added to the project for the `Google.Protobuf` and
`Grpc.Core` assemblies, the example client can be implemented.

```C#
using Grpc.Core;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Walletrpc;

namespace Example
{
    static class Program
    {
        static void Main(string[] args)
        {
            ExampleAsync().Wait();
        }

        static async Task ExampleAsync()
        {
            // Before the gRPC native library (gRPC Core) is lazily loaded and initialized,
            // an environment variable must be set so BoringSSL is configured to use ECDSA TLS
            // certificates (required by btcwallet).
            Environment.SetEnvironmentVariable("GRPC_SSL_CIPHER_SUITES", "HIGH+ECDSA");

            var walletAppData = Portability.LocalAppData(Environment.OSVersion.Platform, "Btcwallet");
            var walletTlsCertFile = Path.Combine(walletAppData, "rpc.cert");
            var cert = await FileUtils.ReadFileAsync(walletTlsCertFile);
            var channel = new Channel("localhost:18332", new SslCredentials(cert));
            try
            {
                var c = WalletService.NewClient(channel);
                var balanceRequest = new BalanceRequest
                {
                    AccountNumber = 0,
                    RequiredConfirmations = 1,
                };
                var balanceResponse = await c.BalanceAsync(balanceRequest);
                Console.WriteLine($"Spendable balance: {balanceResponse.Spendable} Satoshis");
            }
            finally
            {
                await channel.ShutdownAsync();
            }
        }
    }

    static class FileUtils
    {
        public static async Task<string> ReadFileAsync(string filePath)
        {
            using (var r = new StreamReader(filePath, Encoding.UTF8))
            {
                return await r.ReadToEndAsync();
            }
        }
    }

    static class Portability
    {
        public static string LocalAppData(PlatformID platform, string processName)
        {
            if (processName == null)
                throw new ArgumentNullException(nameof(processName));
            if (processName.Length == 0)
                throw new ArgumentException(nameof(processName) + " may not have zero length");

            switch (platform)
            {
                case PlatformID.Win32NT:
                    return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        ToUpper(processName));
                case PlatformID.MacOSX:
                    return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal),
                        "Library", "Application Support", ToUpper(processName));
                case PlatformID.Unix:
                    return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal),
                        ToDotLower(processName));
                default:
                    throw new PlatformNotSupportedException($"PlatformID={platform}");
            }
        }

        private static string ToUpper(string value)
        {
            var firstChar = value[0];
            if (char.IsUpper(firstChar))
                return value;
            else
                return char.ToUpper(firstChar) + value.Substring(1);
        }

        private static string ToDotLower(string value)
        {
            var firstChar = value[0];
            return "." + char.ToLower(firstChar) + value.Substring(1);
        }
    }
}
```

## Node.js

First, install gRPC (either by building the latest source release, or
by installing a gRPC binary development package through your operating
system's package manager).  This is required to install the npm module
as it wraps the native C library (gRPC Core) with C++ bindings.
Installing the [grpc module](https://www.npmjs.com/package/grpc) to
your project can then be done by executing:

```
npm install grpc
```

A Node.js client does not require generating JavaScript stub files for
the wallet's API from the `.proto`.  Instead, a call to `grpc.load`
with the `.proto` file path dynamically loads the Protobuf descriptor
and generates bindings for each service.  Either copy the `.proto` to
the client project directory, or reference the file from the
`btcwallet` project directory.

```JavaScript
// Before the gRPC native library (gRPC Core) is lazily loaded and
// initialized, an environment variable must be set so BoringSSL is
// configured to use ECDSA TLS certificates (required by btcwallet).
process.env['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA';

var fs = require('fs');
var path = require('path');
var os = require('os');
var grpc = require('grpc');
var protoDescriptor = grpc.load('./api.proto');
var walletrpc = protoDescriptor.walletrpc;

var certPath = path.join(process.env.HOME, '.btcwallet', 'rpc.cert');
if (os.platform == 'win32') {
    certPath = path.join(process.env.LOCALAPPDATA, 'Btcwallet', 'rpc.cert');
} else if (os.platform == 'darwin') {
    certPath = path.join(process.env.HOME, 'Library', 'Application Support',
        'Btcwallet', 'rpc.cert');
}

var cert = fs.readFileSync(certPath);
var creds = grpc.credentials.createSsl(cert);
var client = new walletrpc.WalletService('localhost:18332', creds);

var request = {
    account_number: 0,
    required_confirmations: 1
};
client.balance(request, function(err, response) {
    if (err) {
        console.error(err);
    } else {
        console.log('Spendable balance:', response.spendable, 'Satoshis');
    }
});
```

## Python

**Note:** gRPC requires Python 2.7.

After installing gRPC Core and Python development headers, `pip`
should be used to install the `grpc` module and its dependencies.
Full instructions for this procedure can be found
[here](https://github.com/grpc/grpc/blob/master/src/python/README.md).

Generate Python stubs from the `.proto`:

```bash
$ protoc -I /path/to/btcsuite/btcwallet/rpc --python_out=. --grpc_out=. \
  --plugin=protoc-gen-grpc=$(which grpc_python_plugin) \
  /path/to/btcwallet/rpc/api.proto
```

Implement the client:

```Python
import os
import platform
from grpc.beta import implementations

import api_pb2 as walletrpc

timeout = 1 # seconds

def main():
    # Before the gRPC native library (gRPC Core) is lazily loaded and
    # initialized, an environment variable must be set so BoringSSL is
    # configured to use ECDSA TLS certificates (required by btcwallet).
    os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA'

    cert_file_path = os.path.join(os.environ['HOME'], '.btcwallet', 'rpc.cert')
    if platform.system() == 'Windows':
        cert_file_path = os.path.join(os.environ['LOCALAPPDATA'], "Btcwallet", "rpc.cert")
    elif platform.system() == 'Darwin':
        cert_file_path = os.path.join(os.environ['HOME'], 'Library', 'Application Support',
                                      'Btcwallet', 'rpc.cert')

    with open(cert_file_path, 'r') as f:
        cert = f.read()
    creds = implementations.ssl_client_credentials(cert, None, None)
    channel = implementations.secure_channel('localhost', 18332, creds)
    stub = walletrpc.beta_create_WalletService_stub(channel)

    request = walletrpc.BalanceRequest(account_number = 0, required_confirmations = 1)
    response = stub.Balance(request, timeout)
    print 'Spendable balance: %d Satoshis' % response.spendable

if __name__ == '__main__':
    main()
```
