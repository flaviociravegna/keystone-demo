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

byte* recv_buffer(size_t* len, int fd_sock){
  read(fd_sock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  read(fd_sock, reply, reply_size);
  *len = reply_size;
  return reply;
}

byte* recv_buffer_agent(size_t* len){
  byte* reply = (byte*)malloc(32);
  read(fd_clientsock_agent, reply, 5);
  *len = 5;
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

int wait_for_agent_message() {
  size_t len;
  void* buffer = recv_buffer(&len, fd_clientsock_agent);

  if( PRINT_MESSAGE_BUFFERS )
    printf("[EH] Got a new message for the AGENT: %s\n",(char *)buffer);

  /* This happens here */
  return 1;
}

void send_report(void* buffer, size_t len)
{
  send_buffer((byte*)buffer, len);
}

void init_network_agent(){
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
    std::cout << "[Agent] Agent waiting for some seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::cout << "[Agent] Performing runtime attestation..." << std::endl;
    enclave->requestRuntimeAttestation();

    // print the report computed
    std::cout << "[Agent] Computed hash: " << std::endl;
    print_hex_data_2((enclave->getRuntimeAttestationReport())->enclave.hash, sizeof((enclave->getRuntimeAttestationReport())->enclave.hash));
  }
}

void run_enclave(Keystone::Enclave *enclave) {
  uintptr_t retval;
  std::cout << "Enclave thread spawned..." << std::endl;
  Keystone::Error rval = enclave->run_with_runtime_attestation_support(&retval);
}

void run_agent(Keystone::Enclave *enclave) {
  // Accept incoming requests and perform attestation
  std::cout << "[Agent] Agent thread spawned..." << std::endl;

  // .... accept request (TODO)
  for (int i = 0; i < 10; i++)
    wait_for_agent_message();

  // Spawn a thread for each request
  std::thread worker(worker_request_runtime_attestation, enclave);


  worker.join();  
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
