# svalkey

[![GoDoc](https://godoc.org/github.com/karantin2020/svalkey?status.png)](https://godoc.org/github.com/karantin2020/svalkey)
[![Coverage Status](https://coveralls.io/repos/karantin2020/svalkey/badge.svg)](https://coveralls.io/r/karantin2020/svalkey)
[![Go Report Card](https://goreportcard.com/badge/github.com/karantin2020/svalkey)](https://goreportcard.com/report/github.com/karantin2020/svalkey)

## Overview  
`svalkey` provides a `Go` native library to securely store metadata using Distributed Key/Value stores (or common databases).

## What it does  
1. Auto marshal/unmarshal data. You can choose `XMLCodec` (with `NewJSONStore`), `JSONCodec` (with  `NewXMLStore`), `GobCodec` (with `NewStore`). Default is `GobCodec` (just call `NewStore` func).  
Store implements `func Put(key string, value interface{},
options *store.WriteOptions) error` which converts value into `[]byte`.  
Store implements `func Get(key string, value interface{},
options *store.ReadOptions) error` which pulls value in `[]byte` from db and converts into needed type.  
2. Auto en/decrypt data with `github.com/minio/sio`. You can choose AES-256-GCM and chacha20-poly1305. Just pass your secret key. To store data `svalkey` derives key for every key/value pair write with `golang.org/x/crypto/hkdf`.  
3. Puts/pulls data into/from db. You can choose local or distributed db that is supported by `github.com/abronan/valkeyrie`.  

## Install  
```
go get -u -v github.com/karantin2020/svalkey
```

The goal of `svalkey` is to abstract common store operations (Get/Put/List/etc.) for multiple distributed and/or local Key/Value store backends thus using the same self-contained codebase to manage them all.

This lib is based on: 
  -  [github.com/abronan/valkeyrie](https://github.com/abronan/valkeyrie) library which includes backend implementations,
  -  [github.com/minio/sio](https://github.com/minio/sio) library which implements the DARE format. It provides an API for secure en/decrypting IO operations using io.Reader and io.Writer

As of now, `svalkey` offers support for `Consul`, `Etcd`, `Zookeeper`, `Redis` (**Distributed** store) and `BoltDB` (**Local** store) with AES-256-GCM and chacha20-poly1305 en/decryption implementations.

## Usage

`svalkey` is meant to be used as an abstraction layer over existing distributed Key/Value stores. It is especially useful if you plan to support `consul`, `etcd` and `zookeeper` using the same codebase.

It is ideal if you plan for something written in Go that should support:

- A simple secure metadata storage, distributed or local

You can also easily implement a *Crypter* interface to use your own crypt algorithm.

You can find examples of usage for `svalkey` in tests.
