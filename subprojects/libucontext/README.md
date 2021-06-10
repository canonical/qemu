# `libucontext`

`libucontext` is a library which provides the `ucontext.h` C API.  Unlike other implementations,
it faithfully follows the kernel process ABI when doing context swaps.

Notably, when combined with `gcompat`, it provides a fully compatible implementation of the ucontext
functions that are ABI compatible with glibc.

Since version 0.13, for some architectures, you can deploy to bare metal using newlib via the
`FREESTANDING=yes` make option.  Systems which use a syscall cannot work this way.  The table
below shows which architecture ports have been adapted to build with `FREESTANDING=yes`.

Adding support for new architectures is easy, but you need to know assembly language for the
target to do it.


## supported features

| Architecture | Works on musl | Syscall | Supports FREESTANDING | Common trampoline |
|--------------|---------------|---------|-----------------------|-------------------|
|    aarch64   | ✓             |         | ✓                     | ✓                 |
|      arm     | ✓             |         | ✓                     | ✓                 |
|     m68k     | ✓             |         | ✓                     | ✓                 |
|     mips     | ✓             |         | ✓                     |                   |
|    mips64    | ✓             |         | ✓                     |                   |
|      ppc     | ✓             | ✓       |                       |                   |
|     ppc64    | ✓             | ✓       |                       |                   |
|    riscv64   | ✓             |         | ✓                     | ✓                 |
|     s390x    | ✓             |         | ✓                     |                   |
|      sh      | ✓             |         | ✓                     | ✓                 |
|      x86     | ✓             |         | ✓                     | ✓                 |
|    x86_64    | ✓             |         | ✓                     | ✓                 |


## building

`libucontext` uses a simple makefile build system.  You should define `ARCH=` at build time, otherwise
the build system will attempt to guess using `uname -m`.

```
$ make ARCH=x86_64
$ make ARCH=x86_64 check
$ make ARCH=x86_64 DESTDIR=out install
```

There are a few options:

* `ARCH`: The architecture libucontext is being built for.  Must be set to one of the architectures
  listed in the feature support table.  If unset, the build system will attempt to guess based on what
  architecture the host is running.  Setting this option explicitly is highly recommended.

* `FREESTANDING`: If this is set to `yes`, the system ucontext.h headers will not be used.  Instead,
  the headers in `arch/${ARCH}/freestanding` will be used for definitions where appropriate.
  Default is `no`.

* `EXPORT_UNPREFIXED`: If this is set to `yes`, the POSIX 2004 names `getcontext`, `setcontext`,
  `swapcontext` and `makecontext` will be provided as weak symbols aliased against their `libucontext_`
  namespaced equivalents.  This is necessary for libucontext to provide these functions on musl
  systems, but you may wish to disable this when using `FREESTANDING` mode to avoid conflicts with
  the target's libc.  Default is `yes`.

* `DESTDIR`: If this variable is set, the installed files will be installed to the specified path instead
  of the system root.

If you have `scdoc` installed, you can build manpages and install them:

```
$ make docs
$ make DESTDIR=out install_docs
```


## caveats

`libucontext`, while largely functionally equivalent does have some differences over traditional POSIX
ucontext functions:

* Saving and restoring the signal mask is not implemented.  This is largely a non-issue because most
  uses of these functions did not modify the signal mask anyway, but saving/restoring the signal mask
  (even though it is unmodified in basically all cases in practice) induces a significant performance
  penalty due to having to make kernel syscalls.

* Only basic GPR registers are saved and restored when context swapping.  The glibc implementation uses
  hardware capability detection to save/restore other register groups, such as the FPU registers or
  vector processing (AltiVec/AVX/NEON) registers.  Adding this capability detection would significantly
  increase the complexity of the project and thus is not implemented.  Support for compiling in code to
  save/restore FPU registers or vector registers may be added in a later release as a build-time
  setting -- for now, we assume a soft-float ABI with no optional processor features.  In practice, this
  does not really matter, code using these functions are unlikely to be impacted by this design
  assumption.
