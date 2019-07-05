# svalkey

[![GoDoc](https://godoc.org/github.com/karantin2020/svalkey?status.png)](https://godoc.org/github.com/karantin2020/svalkey)
[![Coverage Status](https://coveralls.io/repos/karantin2020/svalkey/badge.svg)](https://coveralls.io/r/karantin2020/svalkey)
[![Go Report Card](https://goreportcard.com/badge/github.com/karantin2020/svalkey)](https://goreportcard.com/report/github.com/karantin2020/svalkey)

## Overview  
`svalkey` provides a `Go` native library to securely store metadata using Distributed Key/Value stores (or common databases).

## Install  
```
go get -u -v github.com/karantin2020/svalkey
```

The goal of `svalkey` is to abstract common store operations (Get/Put/List/etc.) for multiple distributed and/or local Key/Value store backends thus using the same self-contained codebase to manage them all.

This lib is based on [github.com/abronan/valkeyrie](https://github.com/abronan/valkeyrie) library which includes backend implementations.

As of now, `svalkey` offers support for `Consul`, `Etcd`, `Zookeeper`, `Redis` (**Distributed** store) and `BoltDB` (**Local** store) with NaCl secret and poly1305 Crypter implementations.

## Usage

`svalkey` is meant to be used as an abstraction layer over existing distributed Key/Value stores. It is especially useful if you plan to support `consul`, `etcd` and `zookeeper` using the same codebase.

It is ideal if you plan for something written in Go that should support:

- A simple secure metadata storage, distributed or local

You can also easily implement a *Crypter* interface to use your own crypt algorithm.

You can find examples of usage for `svalkey` in tests.
