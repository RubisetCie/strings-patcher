# Strings Patcher

**Strings Patcher** is a tool to patch and replace strings in an already compiled binary (supports Linux ELF and Windows PE).

It's features are the following:

- Replace exact matches.
- Match and replace by substitution.
- Supports multiple encoding (`UTF-8`, `ISO8859-1`, `WINDOWS-1258`, etc)

Patching strings has a limitation: it's **impossible to replace a string with one longer than the original one, only shorter**!

**Beware, modifying random strings in a compiled executable is dangerous and can corrupt it! Please proceed with caution and make backups!**

## Building

Building *string-patcher* can be done using GNU Make:

```
make
```

For building on Windows, you might need to link `libiconv`:

```
make LDFLAGS='-liconv'
```

In order to disable the encoding feature (if `libiconv` is not available for example), you can define a macro:

```
make CFLAGS='-DNO_ENCODING'
```

## Install

To install *string-patcher*, run the following target:

```
make install PREFIX=(prefix)
```

The variable `PREFIX` defaults to `/usr/local`.

## Uninstall

To uninstall *string-patcher*, run the following target using the same prefix as specified in the install process:

```
make uninstall PREFIX=(prefix)
```
