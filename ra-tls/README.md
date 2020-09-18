# Configure SGX RA settings
``` shell
export SPID=<hex string>
export EPID_SUBSCRIPTION_KEY=<hex string>
export QUOTE_TYPE=<SGX_LINKABLE_SIGNATURE | SGX_UNLINKABLE_SIGNATURE>
```

# Build
``` shell
cd $src/ra-tls
make
```

# Run
``` shell
mkdir -p /run/rune
cd build/bin
./ra-tls-server run &
./elv echo
```

# Trouble shooting
## parse_response_header assertion
```
ra-tls-server: untrusted/ias-ra.c:153: parse_response_header: Assertion `sig_begin != ((void *)0)' failed.
./run.sh: line 5: 49050 Aborted                 ./ra-tls-server -s
```

This error is caused due to invalid SGX RA settings. Please configure SGX RA settings with valid values.
