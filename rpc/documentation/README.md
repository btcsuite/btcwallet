# RPC Documentation

This project provides a [gRPC](http://www.grpc.io/) server for Remote Procedure
Call (RPC) access from other processes.  This is intended to be the primary
means by which users, through other client programs, interact with the wallet.

These documents cover the documentation for both consumers of the server and
developers who must make changes or additions to the API and server
implementation:

- [API specification](./api.md)
- [Client usage](./clientusage.md)
- [Making API changes](./serverchanges.md)

A legacy RPC server based on the JSON-RPC API of Bitcoin Core's wallet is also
available, but documenting its usage is out of scope for these documents.
