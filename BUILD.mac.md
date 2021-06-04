Instructions for building and running QEMU on Macs
==================================================

Building
--------
### Build dependencies
In order to build QEMU on Mac, there are few build dependencies needed to be installed.

    brew install meson pkg-config glib pixman

### The QEMU branch to use
There is a `qemu-multipass` branch which should be used.

This branch is v6.0.0 with one cherry-pick from `master` to make building on Big Sur possible, the qemu-6.0.0.patch from the UTM project already applied, and a way to disable building tests.

### Get the submodules
The firmware, etc. are submodules in the project.  To get them, do

    git submodule update --init --recursive --depth 1

### Configuring and compiling
The following configuration is a pretty minimal build of QEMU that works with what we need for Multipass.  In the top-level qemu source directory, issue the following configure command:

    ./configure --target-list=$(cpu-type)-softmmu --disable-bochs --disable-cloop --disable-docs --disable-guest-agent --disable-parallels --disable-vdi --disable-qed --disable-sheepdog --disable-vnc --disable-xen --disable-dmg --disable-replication --disable-hax --disable-snappy --disable-lzo --disable-live-block-migration --disable-vvfat --disable-curl --disable-tests --disable-tcg

where `$(cpu-type)` is either `x86_64` or `aarch64`.

The just run `make -jX` and substitute "X" with number of cores you'd like to use.  For example,

    make -j4
