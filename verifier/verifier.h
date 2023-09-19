#ifndef _TRUSTED_CLIENT_H_
#define _TRUSTED_CLIENT_H_

#include <stdio.h>
#include "calc_msg.h"

#include <string>
#include <iostream>
#include <fstream>
#include "report.h"
//#include "verifier.h"


typedef unsigned char byte;

void verifier_exit();
void verifier_get_boot_report(void* buffer, int ignore_valid);
void send_exit_message();
void send_wc_message(char* buffer);
calc_message_t* generate_wc_message(char* buffer, size_t buffer_len, size_t* finalsize);
calc_message_t* generate_exit_message(size_t* finalsize);

std::string char_to_hex_str(unsigned char c);
void hex_string_to_bytes(const std::string& hexString, unsigned char* buffer);
std::string get_sm_hash_as_string();
std::string get_enclave_boot_hash_as_string();
std::string get_enclave_rt_hash_from_report_buffer(void* buffer);
bool verifier_verify_runtime_report(
  void* buffer,
  std::string enclave_runtime_ref_value,
  std::string sm_ref_value,
  std::string lak_pub,
  std::string nonce_ref_value);

#endif /* _TRUSTED_CLIENT_H_ */
