# set paths for mbedtls and compler for non-riscv target
set(CMAKE_C_COMPILER /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/bin/g++)
set(CMAKE_ASM_COMPILER /usr/bin/gcc)
set(CMAKE_LINKER /usr/bin/ld)

set(MBEDTLS_LIB_CRYPTO_HOST ${MBEDTLS_DIR_HOST}/build/library/libmbedcrypto.a)
set(MBEDTLS_LIB_TLS_HOST ${MBEDTLS_DIR_HOST}/build/library/libmbedtls.a)
set(MBEDTLS_LIB_X509_HOST ${MBEDTLS_DIR_HOST}/build/library/libmbedx509.a)

set(my_mbedtls_files ../my_mbedtls_stdlib/custom_asn1.c ../my_mbedtls_stdlib/custom_ed25519.c ../my_mbedtls_stdlib/custom_pk.c ../my_mbedtls_stdlib/custom_md.c ../my_mbedtls_stdlib/custom_utils.c
../my_mbedtls_stdlib/custom_attester.c ../my_mbedtls_stdlib/custom_string.c ../my_mbedtls_stdlib/custom_x509.c ../my_mbedtls_stdlib/custom_x509_crt.c ../my_mbedtls_stdlib/custom_x509_csr.c)
set(my_mbedtls_dir ../my_mbedtls_stdlib/)
set(sha3_dir ../my_mbedtls_stdlib/sha3/)
set(ed25519_files ../my_mbedtls_stdlib/ed25519/ed25519.h ../my_mbedtls_stdlib/ed25519/fe.h ../my_mbedtls_stdlib/ed25519/fe.c ../my_mbedtls_stdlib/ed25519/fixedint.h
../my_mbedtls_stdlib/ed25519/ge.h ../my_mbedtls_stdlib/ed25519/ge.c ../my_mbedtls_stdlib/ed25519/keypair.c ../my_mbedtls_stdlib/ed25519/precomp_data.h
../my_mbedtls_stdlib/ed25519/sc.h ../my_mbedtls_stdlib/ed25519/sc.c ../my_mbedtls_stdlib/ed25519/sign.c ../my_mbedtls_stdlib/ed25519/verify.c)

# ********** trusted client (Verifier non-riscv)*********
set(MBEDTLS_DIR_HOST_NON_RISCV $ENV{MBEDTLS_DIR_HOST_NON_RISCV})
set(MBEDTLS_LIB_CRYPTO_HOST_STD ${MBEDTLS_DIR_HOST_NON_RISCV}/build/library/libmbedcrypto.a)
set(MBEDTLS_LIB_TLS_HOST_STD ${MBEDTLS_DIR_HOST_NON_RISCV}/build/library/libmbedtls.a)
set(MBEDTLS_LIB_X509_HOST_STD ${MBEDTLS_DIR_HOST_NON_RISCV}/build/library/libmbedx509.a)

add_executable(verifier_unix
  client.cpp
  verifier.cpp
  db_access.cpp
  ../include/enclave_expected_hash.h
  ../include/sm_expected_hash.h
  sqlite-amalgamation-3420000/sqlite3.c
  cert_verifier.c
  ${my_mbedtls_files} ${sha3_dir}/sha3.h ${sha3_dir}/sha3.c ${ed25519_files}
)

target_link_libraries(verifier_unix
  ${KEYSTONE_LIB_VERIFIER_NON_RISCV}
  ${CMAKE_DL_LIBS}
  ${MBEDTLS_LIB_TLS_HOST_STD} ${MBEDTLS_LIB_X509_HOST_STD} ${MBEDTLS_LIB_CRYPTO_HOST_STD}
  Threads::Threads
)

target_include_directories(verifier_unix
  PRIVATE ${MBEDTLS_DIR_HOST_NON_RISCV}/include
  PRIVATE ${my_mbedtls_dir}/include
  PRIVATE ${my_mbedtls_dir}
  PRIVATE ${sha3_dir}  
  PRIVATE .
)