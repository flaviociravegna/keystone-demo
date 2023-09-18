#include <string.h>
#include <sstream>
#include <iomanip> // For std::hex

#include "trusted_client.h"
#include "client.h"

#include "test_dev_key.h"
#include "enclave_expected_hash.h"
#include "sm_expected_hash.h"

/*
unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];*/

int double_fault;
int channel_ready;


void trusted_client_exit(){
  if(double_fault || !channel_ready){
    printf("DC: Fatal error, exiting. Remote not cleanly shut down.\n");
    exit(-1);
  }
  else{
    double_fault = 1;
    printf("[VER] Exiting. Attempting clean remote shutdown.\n");
    send_exit_message();
    exit(0);
  }
}
/*
void trusted_client_init(){

  if( sodium_init() != 0){
    printf("[VER] Libsodium init failure\n");
    trusted_client_exit();
  }
  if( crypto_kx_keypair(client_pk,client_sk) != 0){
    printf("[VER] Libsodium keypair gen failure\n");
    trusted_client_exit();
  }

  channel_ready = 0;
}

byte* trusted_client_pubkey(size_t* len){
  *len = crypto_kx_PUBLICKEYBYTES;
  return (byte*)client_pk;
}
*/
void trusted_client_get_report(void* buffer, int ignore_valid){

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
      trusted_client_exit();
    }
  }
  if(report.getDataSize() !=  32){
    printf("[VER] Bad report data sec size\n");
    trusted_client_exit();
  }
  
  channel_ready = 1;
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))
/*
byte* trusted_client_box(byte* msg, size_t size, size_t* finalsize){
  size_t size_padded = BLOCK_UP(size);
  *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
  byte* buffer = (byte*)malloc(*finalsize);
  if(buffer == NULL){
    printf("[VER] NOMEM for msg\n");
    trusted_client_exit();
  }

  memcpy(buffer, msg, size);

  size_t buf_padded_len;
  if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0) {
    printf("[VER] Unable to pad message, exiting\n");
    trusted_client_exit();
  }

  unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

  if(crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0){
    printf("[VER] secretbox failed\n");
    trusted_client_exit();
  }

  return(buffer);
}

void trusted_client_unbox(unsigned char* buffer, size_t len){

  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(buffer[clen]);
  if (crypto_secretbox_open_easy(buffer, buffer, clen, nonceptr, rx) != 0){
    printf("[VER] unbox failed\n");
    trusted_client_exit();
  }

  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
  size_t unpad_len;
  if( sodium_unpad(&unpad_len, buffer, ptlen, MSG_BLOCKSIZE) != 0){
    printf("[VER] Invalid message padding, ignoring\n");
    trusted_client_exit();
  }


  return;
}
int trusted_client_read_reply(unsigned char* data, size_t len){

  trusted_client_unbox(data, len);

  int* replyval = (int*)data;

  printf("[VER] Enclave said string was %i words long\n",*replyval);

}
*/

void send_exit_message(){

  size_t pt_size;
  calc_message_t* pt_msg = generate_exit_message(&pt_size);
  byte* bytes_msg = (byte*)malloc(pt_size);
  memcpy(bytes_msg, pt_msg, pt_size);
  send_buffer(bytes_msg, pt_size);
  //size_t ct_size;
  //byte* ct_msg = trusted_client_box((byte*)pt_msg, pt_size, &ct_size);


  free(pt_msg);
  free(bytes_msg);
}

void send_wc_message(char* buffer){

  size_t pt_size;
  calc_message_t* pt_msg = generate_wc_message(buffer, strlen(buffer)+1, &pt_size);
  byte* bytes_msg = (byte*)malloc(pt_size);
  memcpy(bytes_msg, pt_msg, pt_size);
  send_buffer(bytes_msg, pt_size);
  //size_t ct_size;
  //byte* ct_msg = trusted_client_box((byte*)pt_msg, pt_size, &ct_size);

  free(pt_msg);
  free(bytes_msg);

}

calc_message_t* generate_wc_message(char* buffer, size_t buffer_len, size_t* finalsize){
  calc_message_t* message_buffer = (calc_message_t*)malloc(buffer_len+sizeof(calc_message_t));

  message_buffer->msg_type = CALC_MSG_WORDCOUNT;
  message_buffer->len = buffer_len;
  memcpy(message_buffer->msg, buffer, buffer_len);

  *finalsize = buffer_len + sizeof(calc_message_t);

  return message_buffer;
};

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
