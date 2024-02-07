# Install the project

1. Install dependencies
   ```bash
   sudo apt update
   sudo apt install python3-pip
   ```

2. Generate the hash of the Security Monitor
   ```bash
   git clone https://github.com/flaviociravegna/keystone-demo
   cd ../keystone/sm/tools
   make hash FW_PATH=../../build/sm.build/platform/generic/firmware
   ```

3. Build the Demo and create a directory for the image into the Keystone build directory
   ```bash
   cd ../../../keystone-demo
   SM_HASH=../keystone/sm/tools/sm_expected_hash.h ./quick-start.sh
   mkdir -p ../keystone/build/overlay/root/keystone-demo
   source ../keystone/source.sh
   ./compile-demo.sh
   ```

# Update the reference values after updating SM or EAPP

1. Open a terminal and navigate to the keystone/build/ folder:
   - Launch QEMU with the `./scripts/run-qemu.sh` script.
   - Login using *root* as username and *sifive* as password.
   - Insert the command `insmod keystone-driver.ko`.
   - Insert the command `cd keystone-demo`.
   - Insert the command `./agent.riscv`.

2. Open another terminal. Navigate to *keystone-demo* folder and launch the following command:
   ```bash
   DEMO_DIR=. ./scripts/get_attestation.sh ./include/
   ```
   It launches a script that will execute (and automatically close) the Verifier application. Finally, it will copy the digests into the expected destination folder.

   Note: if the verifier does not shut down, simply close it pressing *CTRL+C*

3. In the *keystone-demo* folder, run again the `./compile-demo.sh` script to build the correct version of the keystone-demo project. At this point, the framework should run as expected

# Launch the framework

1. Into the *keystone* root directory
   - run Qemu
      ```bash
      ./build/scripts/run-qemu.sh
      ```
   - launch the Agent after the login
      ```bash
      insmod keystone-driver.ko
      cd keystone-demo
      ./agent.riscv
      ```
2. Into the *keystone-demo* root directory, launch the verifier
      ```bash
      cd build/verifier/
      ./verifier_unix 127.0.0.1
      ```