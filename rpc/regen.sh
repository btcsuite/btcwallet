#!/bin/sh

protoc -I. api.proto --go_out=plugins=grpc:walletrpc
