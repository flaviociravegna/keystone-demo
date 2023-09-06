cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)
project(KeystoneDemo)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{LIBSODIUM_CLIENT_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_CLIENT_DIR")
endif()
set(LIBSODIUM_CLIENT_DIR $ENV{LIBSODIUM_CLIENT_DIR})

if (NOT DEFINED ENV{LIBSODIUM_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_DIR")
endif()
set(LIBSODIUM_DIR $ENV{LIBSODIUM_DIR})

if (NOT DEFINED ENV{MBEDTLS_DIR_HOST})
  message(FATAL_ERROR "Please set MBEDTLS_DIR_HOST")
endif()
set(MBEDTLS_DIR_HOST $ENV{MBEDTLS_DIR_HOST})

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()

use_riscv_toolchain(${BITS})

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

# find program "makeself"
find_program(MAKESELF makeself)
# multi-threading support
find_package(Threads REQUIRED)

# Your project setup, including include directories and target_link_libraries
# export include directory
include_directories(include
  ${LIBSODIUM_CLIENT_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier
)

# trusted client
add_subdirectory(trusted_client)

# trusted client (non-RISC-V version)
#add_executable(trusted_client_linux_version
#  trusted_client/client.cpp
#  trusted_client/trusted_client.cpp
#  trusted_client/db_access.cpp
#  include/enclave_expected_hash.h
#  include/sm_expected_hash.h
#  trusted_client/sqlite-amalgamation-3420000/sqlite3.c
#)

#target_link_libraries(trusted_client_linux_version
#  ${LIBSODIUM_CLIENT_DIR}/.libs/libsodium.a
#  ${CMAKE_DL_LIBS}
#  Threads::Threads
#)

# enclave
add_subdirectory(server_eapp)
set(host_bin demo-server.riscv)
set(host_src enclave-host.cpp edge_wrapper.cpp)
set(eyrie_plugins "freemem")
set(package_name "demo-server.ke")
set(package_script "./demo-server.riscv")

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER} Threads::Threads)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_keystone_package(packagedemo
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} server_eapp/server_eapp.eapp_riscv ${host_bin})

add_dependencies(packagedemo ${eapp_bin}-eyrie)
