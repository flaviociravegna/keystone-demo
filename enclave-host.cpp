#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include "keystone.h"
#include "edge_wrapper.h"
#include "encl_message.h"

#define PRINT_MESSAGE_BUFFERS 1

/* We hardcode these for demo purposes. */
const char* enc_path = "server_eapp.eapp_riscv";
const char* runtime_path = "eyrie-rt";

/* Temp: to move from here*/
const char ca_cert_pem[] = 
  "-----BEGIN CERTIFICATE-----\r\n"                                       \
  "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\r\n"  \
  "QMpPIe8Pig==\r\n"                                                      \
  "-----END CERTIFICATE-----\r\n";
unsigned long ca_cert_pem_len = sizeof(ca_cert_pem);

#define PORTNUM_AGENT 8068
#define PORTNUM 8067
int fd_clientsock;
int fd_clientsock_agent;
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN], local_buffer_agent[BUFFERLEN];

void send_buffer(byte* buffer, size_t len){
  write(fd_clientsock, &len, sizeof(size_t));
  write(fd_clientsock, buffer, len);
}

void send_buffer_agent(byte* buffer, size_t len, bool is_sending_cert) {
  if (is_sending_cert)
    write(fd_clientsock_agent, &ca_cert_pem_len, sizeof(size_t));
  write(fd_clientsock_agent, buffer, len);
}

// Format: <len_cert_sm><len_cert_root><len_cert_man><cert_sm><cert_root><len_cert_man>
void send_cert_chain_on_buffer_agent(
        unsigned char *sm_cert_par,
        unsigned char *root_cert_par,
        unsigned char *man_cert_par,
        size_t sm_cert_len,
        size_t root_cert_len,
        size_t man_cert_len) {
  // Writing the 3 lengths
  write(fd_clientsock_agent, &sm_cert_len, sizeof(size_t));
  write(fd_clientsock_agent, &root_cert_len, sizeof(size_t));
  write(fd_clientsock_agent, &man_cert_len, sizeof(size_t));

  // Writing the 3 certificates
  write(fd_clientsock_agent, (byte *) sm_cert_par, sm_cert_len);
  write(fd_clientsock_agent, (byte *) root_cert_par, root_cert_len);
  write(fd_clientsock_agent, (byte *) man_cert_par, man_cert_len);
}

byte* recv_buffer(size_t* len, int fd_sock){
  read(fd_sock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  read(fd_sock, reply, reply_size);
  *len = reply_size;
  return reply;
}

byte* recv_buffer_agent(size_t* len){
  byte* reply = (byte*)malloc(BUFFERLEN);
  read(fd_clientsock_agent, reply, BUFFERLEN);
  *len = BUFFERLEN;
  return reply;
}

void print_hex_data(unsigned char* data, size_t len){
  unsigned int i;
  std::string str;
  for(i=0; i<len; i+=1){
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();
    if(i>0 && (i+1)%8 == 0){
      if((i+1)%32 == 0){
	str += "\n";
      }
      else{
	str += " ";
      }
    }
  }
  printf("%s\n\n",str.c_str());
}

void print_hex_data_2(unsigned char* data, size_t len){
  unsigned int i;
  std::string str;
  for (i = 0; i < len; i += 1) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();
    if(i > 0 && (i + 1) % 32 == 0)
	      str += "\n";
  }
  printf("%s\n\n",str.c_str());
}

unsigned long print_buffer(char* str){
  printf("[SE] %s",str);
  return strlen(str);
}

void print_value(unsigned long val){
  printf("[SE] value: %u\n",val);
  return;
}

void send_reply(void* data, size_t len){
  printf("[EH] Sending encrypted reply:\n");

  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)data, len);

  send_buffer((byte*)data, len);
}

void* wait_for_client_pubkey(){
  size_t len;
  return recv_buffer(&len, fd_clientsock);
}

encl_message_t wait_for_message(){

  size_t len;

  void* buffer = recv_buffer(&len, fd_clientsock);

  printf("[EH] Got an encrypted message:\n");
  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)buffer, len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

int wait_for_agent_message(Keystone::Enclave *enclave) {
  size_t len;
  std::cout << "[Agent] Waiting for a message..." << std::endl;
  char* buffer = (char *)recv_buffer(&len, fd_clientsock_agent);

  // Send the certificates
  if (buffer[0] == '1' && buffer[1] == '\0') {
    std::cout << "[Agent] Requesting certificates..." << std::endl;
    /*
    byte* certificate_bytes = reinterpret_cast<byte*>(const_cast<char*>(ca_cert_pem));
    send_buffer_agent(certificate_bytes, ca_cert_pem_len, true);*/
    unsigned char cert_sm[512];
    unsigned char cert_root[512];
    unsigned char cert_man[512];
    int lengths[3];
    enclave->requestCertChain(cert_sm, cert_root, cert_man, lengths);

    printf("[Agent] Received lengths: l1: %d, l2: %d, l3: %d\n", lengths[0], lengths[1], lengths[2]);
    send_cert_chain_on_buffer_agent(cert_sm, cert_root, cert_man, lengths[0], lengths[1], lengths[2]);

  } else {
    std::cout << "[Agent] Other operations..." << std::endl;
  }

  return 1;
}

void send_report(void* buffer, size_t len)
{
  send_buffer((byte*)buffer, len);
}

void init_network_agent() {
  struct sockaddr_in server_addr, client_addr;
  int fd_sock = socket(AF_INET, SOCK_STREAM, 0);

  if (fd_sock < 0){
    printf("Failed to open socket\n");
    exit(-1);
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORTNUM_AGENT);

  if(bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
    printf("Failed to bind socket\n");
    exit(-1);
  }

  listen(fd_sock, 2);

  socklen_t client_len = sizeof(client_addr);
  fd_clientsock_agent = accept(fd_sock, (struct sockaddr*)&client_addr, &client_len);

  if (fd_clientsock_agent < 0){
    printf("No valid client socket\n");
    exit(-1);
  }
}

void init_network_wait(){
  int fd_sock;
  struct sockaddr_in server_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0){
    printf("Failed to open socket\n");
    exit(-1);
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORTNUM);
  if( bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
    printf("Failed to bind socket\n");
    exit(-1);
  }
  listen(fd_sock,2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr*)&client_addr, &client_len);
  if (fd_clientsock < 0){
    printf("No valid client socket\n");
    exit(-1);
  }
}

void worker_request_runtime_attestation(Keystone::Enclave *enclave) {
  for (int i = 0; i < 3; i++) {
    std::cout << "ok " << std::endl;
    /*
    std::cout << "[Agent] Agent waiting for some seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::cout << "[Agent] Performing runtime attestation..." << std::endl;
    enclave->requestRuntimeAttestation();

    // print the report computed
    std::cout << "[Agent] Computed hash: " << std::endl;
    print_hex_data_2((enclave->getRuntimeAttestationReport())->enclave.hash, sizeof((enclave->getRuntimeAttestationReport())->enclave.hash));
    */
  }
}

void run_agent(Keystone::Enclave *enclave) {
  // Accept incoming requests and perform attestation
  std::cout << "[Agent] Agent initialized" << std::endl;

  // .... accept requests
  for (int i = 0; i < 10; i++)
    wait_for_agent_message(enclave);

  // Spawn a thread for each request
  std::thread worker(worker_request_runtime_attestation, enclave);
  worker.join();  
}

void run_enclave(Keystone::Enclave *enclave) {
  uintptr_t retval;
  //std::cout << "Enclave thread spawned..." << std::endl;
  Keystone::Error rval = enclave->run_with_runtime_attestation_support(&retval);
}

int main(int argc, char** argv)
{
  /* Wait for network connection */
  init_network_wait();
  init_network_agent();

  printf("[EH] Got connection from remote client\n");


  Keystone::Enclave enclave;
  Keystone::Params params;

  if(enclave.init(enc_path, runtime_path, params) != Keystone::Error::Success){
    printf("HOST: Unable to start enclave\n");
    exit(-1);
  }

  edge_init(&enclave);

  std::thread thread_enclave(run_enclave, &enclave);
  std::thread thread_agent(run_agent, &enclave);

  thread_enclave.join();
  thread_agent.join();

  return 0;
}
