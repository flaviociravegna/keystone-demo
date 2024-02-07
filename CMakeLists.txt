cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)
project(KeystoneDemo)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{KEYSTONE_SDK_NON_RISCV_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_NON_RISCV_DIR environment variable to an installed SDK path")
endif()

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

set(KEYSTONE_SDK_NON_RISCV_DIR $ENV{KEYSTONE_SDK_NON_RISCV_DIR})
set(KEYSTONE_LIB_VERIFIER_NON_RISCV ${KEYSTONE_SDK_NON_RISCV_DIR}/lib/libkeystone-verifier-non-riscv.a)

# find program "makeself"
find_program(MAKESELF makeself)
# multi-threading support
find_package(Threads REQUIRED)

# Your project setup, including include directories and target_link_libraries
# export include directory
include_directories(include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier
)

# trusted client
add_subdirectory(verifier)

# enclave
add_subdirectory(server_eapp)

# agent
set(host_bin agent.riscv)
set(host_src agent.cpp edge_wrapper.cpp)
set(eyrie_plugins "freemem")
set(package_name "agent.ke")
set(package_script "./agent.riscv")

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER} Threads::Threads pthread)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_keystone_package(packagedemo
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} server_eapp/server_eapp.eapp_riscv ${host_bin})

add_dependencies(packagedemo ${eapp_bin}-eyrie)
