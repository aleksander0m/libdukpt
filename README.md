
# libdukpt

libdukpt is a small **[C library](https://aleksander0m.github.io/libdukpt/)**
that allows performing *key generation* as well as *encryption and decryption*
operations using the
**[DUKPT](https://en.wikipedia.org/wiki/Derived_unique_key_per_transaction)**
key management scheme.

## Building

### options and dependencies

The basic dependencies to build the libdukpt project are **openssl** and
**gtk-doc** (only if building from a git checkout).

On a Debian based system, the dependencies may be installed as follows:
```
$ sudo apt-get install libssl-dev gtk-doc-tools
```

### configure, compile and install

```
$ NOCONFIGURE=1 ./autogen.sh     # only needed if building from git
$ ./configure --prefix=/usr
$ make
$ sudo make install
```

## License

This project is licensed under the LGPLv2.1+ license.

* Copyright © 2017 Zodiac Inflight Innovations
* Copyright © 2017 Aleksander Morgado <aleksander@aleksander.es>
