# Fuzz Testing for OpenLDAP

This directory contains fuzz targets for OpenLDAP's parsing subsystems,
designed for use with [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
and [OSS-Fuzz](https://github.com/google/oss-fuzz).

## Fuzz targets

| Target | Description |
|--------|-------------|
| `fuzz_ldap_dn` | Fuzzes LDAP Distinguished Name parsing (RFC 4514) |

## Building locally

```bash
clang -g -fsanitize=fuzzer,address fuzz_ldap_dn.c -o fuzz_ldap_dn
./fuzz_ldap_dn corpus/
```

## OSS-Fuzz integration

These targets are continuously fuzzed via Google's OSS-Fuzz infrastructure.
