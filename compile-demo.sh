cd build
make
make packagedemo
cp demo-server.ke demo-server.riscv trusted_client.riscv ../../keystone/build/overlay/root/keystone-demo/
cd ../../keystone/build
make image

