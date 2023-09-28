#include <string.h>
#include <sstream>
#include <iomanip> // For std::hex

#include "test_dev_key.h"
#include "./include/verifier.h"
#include "sm_expected_hash.h"
#include "enclave_expected_hash.h"

bool verifier_verify_boot_report(void* buffer, int ignore_valid){

  Report report;
  report.fromBytes((unsigned char*)buffer);
  report.printPretty();

  printf("[VER] Verification of the boot-time attestation report...\n");
  if (report.verify(enclave_expected_hash,
  		    sm_expected_hash,
  		    _sanctum_dev_public_key))
  {
    printf("[VER] Attestation signature and enclave hash are valid\n");
  }
  else
  {
    printf("[VER] Attestation report is NOT valid\n");
    if( ignore_valid ){
      printf("[VER] Ignore Validation was set, CONTINUING WITH INVALID REPORT\n");
    }
    else{
      return false;
    }
  }
  
  if(report.getDataSize() !=  32){
    printf("[VER] Bad report data sec size\n");
    return false;
  }

  return true;
}

byte* get_exit_message(size_t *pt_size) {
  calc_message_t* pt_msg = generate_exit_message(pt_size);
  byte* bytes_msg = (byte*)malloc(*pt_size);
  memcpy(bytes_msg, pt_msg, *pt_size);
  free(pt_msg);
  return bytes_msg;
}

calc_message_t* generate_exit_message(size_t* finalsize){

  calc_message_t* message_buffer = (calc_message_t*)malloc(sizeof(calc_message_t));
  message_buffer->msg_type = CALC_MSG_EXIT;
  message_buffer->len = 0;

  *finalsize = sizeof(calc_message_t);

  return message_buffer;

}

/******************* New Functions *********************/

// Function to convert a single unsigned char to a hexadecimal string
std::string char_to_hex_str(unsigned char c) {
  std::stringstream ss;
  ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  return ss.str();
}

void hex_string_to_bytes(const std::string& hexString, unsigned char* buffer) {
    std::istringstream hexStream(hexString);
    unsigned int byteValue, index = 0;

    while (hexStream >> std::hex >> byteValue)
        buffer[index++] = static_cast<unsigned char>(byteValue);
}

std::string get_sm_hash_as_string() {
  std::stringstream ss;
  for (int i = 0; i < sm_expected_hash_len; ++i)
    // Convert each unsigned char to its hexadecimal representation
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sm_expected_hash[i]);
  
  return ss.str();
}

std::string get_enclave_boot_hash_as_string() {
  std::stringstream ss;
  for (int i = 0; i < enclave_expected_hash_len; ++i)
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(enclave_expected_hash[i]);
  
  return ss.str();
}

std::string get_enclave_rt_hash_from_report_buffer(void* buffer) {
  Report report;
  report.fromBytesRuntime((unsigned char*)buffer);
  byte* hash = report.getEnclaveRuntimeHash();

  std::string hash_str = "";
  for (int i = 0; i < enclave_expected_hash_len; ++i)
    hash_str += char_to_hex_str((unsigned char) hash[i]);

  return hash_str;
}

bool verifier_verify_runtime_report(
  void* buffer,
  std::string enclave_runtime_ref_value,
  std::string sm_ref_value,
  std::string lak_pub,
  std::string nonce_ref_value) {
  Report report;
  report.fromBytesRuntime((unsigned char*)buffer);

  if(memcmp(report.getNonceRuntime(), nonce_ref_value.c_str(), 32) == 0){
    printf("[VER] The nonce is different from the expected one\n");
    return false;
  }

  // <_sanctum_dev_public_key> provided "in test_dev_key.h"
  byte eappRefArray[enclave_expected_hash_len];
  byte smRefArray[sm_expected_hash_len];
  byte lakRefArray[32];

  report.HexToBytes(eappRefArray, enclave_expected_hash_len, enclave_runtime_ref_value);
  report.HexToBytes(smRefArray, sm_expected_hash_len, sm_ref_value);
  report.HexToBytes(lakRefArray, 32, lak_pub);

  if (report.verifyRuntimeReport(eappRefArray, smRefArray, _sanctum_dev_public_key, lakRefArray))
    printf("[VER] Attestation signature and enclave hash are valid\n");
  else {
    printf("[VER] Attestation report is NOT valid\n");
    return false;
  }

  return true;
}
