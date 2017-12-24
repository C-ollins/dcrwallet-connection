#!/bin/bash
echo "Installing packages"
go get "github.com/decred/dcrwallet/rpc/walletrpc"
go get "golang.org/x/net/context"
go get "google.golang.org/grpc"
go get "github.com/decred/dcrd/dcrutil"