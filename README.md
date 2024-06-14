# aea1meta

AppleEncryptedArchive metadata dumper.

### Building

```
make
```

For HPKE support (`-k`, requires OpenSSL):

```
HPKE=1 OPENSSL=1 make
```

### Usage

```
./aea1meta file.aea              - Dump all props as JSON
./aea1meta file.aea [prop]       - Dump single prop value raw
./aea1meta -l file.aea           - Dump prop names, one per line
./aea1meta -k file.aea [key.pem] - Print archive decryption key
```

### Credits

Thanks to @dhinakg and @nicolas17 for helping me figure this out.

### License

[MIT](https://github.com/Siguza/aea1meta/blob/master/LICENSE).
