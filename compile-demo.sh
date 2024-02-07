export DEMO_DIR=$(pwd)
#DEMO_DIR=. ./scripts/get_attestation.sh ./include/

mkdir -p mbedtls_builds
cd mbedtls_builds

if [ ! -d mbedtls_host_non_riscv ]
then
  git clone https://github.com/Mbed-TLS/mbedtls.git mbedtls_host_non_riscv
  cd mbedtls_host_non_riscv
  git checkout 3c3b94a31b9d91e1579c48165658486171c82a36
  python3 -m pip install --user -r scripts/basic.requirements.txt
  mkdir build && cd build
  cmake ..
  cmake --build .
  cd ../..
fi

export MBEDTLS_DIR_HOST=$(pwd)/mbedtls_host
export MBEDTLS_DIR_HOST_NON_RISCV=$(pwd)/mbedtls_host_non_riscv

cd ..
mkdir -p build
cd build
export KEYSTONE_SDK_NON_RISCV_DIR=$(pwd)/../../keystone/sdk_std/build64
cmake ..
make
make packagedemo
cp agent.ke agent.riscv ./verifier/verifier_unix server_eapp/server_eapp.eapp_riscv eyrie-rt ../../keystone/build/overlay/root/keystone-demo/
cd verifier
mkdir -p db
cd ../../../keystone/build 
make image

