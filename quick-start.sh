#!/bin/bash

set -e

echo -e "This is a quick-start build script for the Keystone Demo, it
will clone and build all the necessary parts to run the demo
server/applcation and client on a RISC-V platform (ex: qemu). Please
ensure you have cloned keystone completely and that you have fully
built the sdk tests and run them successfully in qemu.

You must set KEYSTONE_SDK_DIR to the install directory of Keystone SDK.

You must have the riscv64 gcc on-path as well. (e.g. run
'source source.sh' in the Keystone directory."

# Check location/tools
if [[ ! -v KEYSTONE_SDK_DIR ]]
then
    echo "KEYSTONE_SDK_DIR not set! Please set this to the location where Keystone SDK has been installed."
    exit 0
fi

if [[ ! -v SM_HASH ]]
then
    echo "SM_HASH is not set! Please follow README to generate the expected hash"
    exit 0
fi

if [[ ! $(command -v riscv64-unknown-linux-gnu-gcc) ]]
then
    echo "No riscv64 gcc available. Make sure you've run \"source source.sh\" in the Keystone directory (or equivalent.)";
    exit 0
fi

DEMO_DIR=$(pwd)

set -e

# Copy the expected hash over
echo "Copying expected sm hash from riscv-pk, this may be incorrect!"
cp $SM_HASH include/
echo "SM hash copied succesfully"

# Build the demo
# export MBEDTLS_DIR_HOST=$(pwd)/mbedtls_host
# export MBEDTLS_DIR_HOST_NON_RISCV=$(pwd)/mbedtls_host_non_riscv
# mkdir -p build
# cd build
# cmake ..
# make
# make packagedemo

# Done!
# echo -e "************ Demo binaries built and copied into overlay directory. ***************
#             Run 'make image' in the Keystone build dir, and the demo binaries should
#             be available in qemu next time you start it!"
