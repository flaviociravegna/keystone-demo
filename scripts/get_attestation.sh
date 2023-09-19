#!/bin/bash

output_path=$1

if [ "${output_path}xxx" = "xxx" ]; then
    echo You must set the directory which will hold the build files to copy over!;
    exit
fi

if [ -z "$KEYSTONE_DIR" -a "${KEYSTONE_DIR+xxx}" = "xxx" ]; then
    echo You MUST set KEYSTONE_DIR.;
    exit
fi

genhash () {
    echo "Generating hash ($2) for \"$1\""
    echo $2 | xxd -r -p - > $1_expected_hash
    xxd -i $1_expected_hash > $1_expected_hash.h
}

extracthash () {
    # Generalize me!
    expect_commands='
    set timeout 60
    cd $::env(DEMO_DIR)/build/verifier/
    spawn ./verifier_unix 127.0.0.1 --ignore-valid

    expect "operation: " { send "q" }
    '
    expect -c "${expect_commands//
/;}"
}

extracthash | tee extract_hash.log
SM_HASH=$(awk '/=== Security Monitor ===/,/=== Enclave Application ===/' extract_hash.log  | grep "Hash: " | cut -c 7-)
EAPP_HASH=$(awk '/=== Enclave Application ===/,/-- Device pubkey --/' extract_hash.log  | grep "Hash: " | cut -c 7-)
rm -f extract_hash.log
cd $output_path
if [ "${SM_HASH}xxx" = "xxx" ]; then
    echo Could not extract the SM_HASH!;
fi
if [ "${EAPP_HASH}xxx" = "xxx" ]; then
    echo Could not extract the EAPP_HASH!;
    exit
fi
genhash sm $SM_HASH
genhash enclave $EAPP_HASH
