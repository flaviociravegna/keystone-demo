#KEYSTONE_DIR=../keystone/build ./scripts/get_attestation.sh ./include/
cd build
export LIBSODIUM_DIR=$(pwd)/../libsodium_builds/libsodium_server/src/libsodium/
export LIBSODIUM_CLIENT_DIR=$(pwd)/../libsodium_builds/libsodium_client/src/libsodium/
cmake ..
make
make packagedemo
cp demo-server.ke demo-server.riscv trusted_client.riscv ../../keystone/build/overlay/root/keystone-demo/
cd ../../keystone/build
make image

