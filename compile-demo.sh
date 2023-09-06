#KEYSTONE_DIR=../keystone/build ./scripts/get_attestation.sh ./include/

DEMO_DIR=$(pwd)

mkdir -p mbedtls_builds
cd mbedtls_builds

if [ ! -d mbedtls_host ]
then
  git clone https://github.com/Mbed-TLS/mbedtls.git mbedtls_host
  cd mbedtls_host
  git checkout 3c3b94a31b9d91e1579c48165658486171c82a36
  python3 -m pip install --user -r scripts/basic.requirements.txt
  mkdir build && cd build
  cmake -DCMAKE_TOOLCHAIN_FILE=$DEMO_DIR/riscv-toolchain.cmake -DENABLE_TESTING=0ff ..
  cmake --build .
  cd ../..
fi

export MBEDTLS_DIR_HOST=$(pwd)/mbedtls_host

cd ../build
export LIBSODIUM_DIR=$(pwd)/../libsodium_builds/libsodium_server/src/libsodium/
export LIBSODIUM_CLIENT_DIR=$(pwd)/../libsodium_builds/libsodium_client/src/libsodium/
cmake ..
make
make packagedemo
cp demo-server.ke demo-server.riscv ./trusted_client/trusted_client.riscv server_eapp/server_eapp.eapp_riscv eyrie-rt ../../keystone/build/overlay/root/keystone-demo/
cd ../../keystone/build 
make image

