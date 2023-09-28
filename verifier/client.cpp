#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <unistd.h>
#include <random>

#include "./include/verifier.h"
#include "./include/client.h"
#include "./include/db_access.h"
extern "C" {
    #include "./include/cert_verifier.h"
}

#include <vector>
#include <sstream>

#include <thread>
#include <chrono>

#define NONCE_LEN 32
#define PORTNUM_AGENT 8068
#define PORTNUM 8067
sqlite3 *db;
int fd_sock, fd_sock_agent;
struct sockaddr_in server_addr, server_addr_agent;
struct hostent *server;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN], local_buffer_agent[BUFFERLEN];


/****************************************************************/
/*********************** NEW FUNCTIONS **************************/
/****************************************************************/

void print_menu() {
  std::cout << std::endl;
  std::cout << "===================================================================================\n";
  std::cout << "-----------------------------------------------------------------------------------\n";
  std::cout << "[VER] Available operations:" << "\n";
  std::cout << "[VER] 1: Request Certificate Chain" << "\n";
  std::cout << "[VER] 2: Perform Runtime Attestation" << "\n";
  std::cout << "[VER] q: Quit" << "\n";
  std::cout << "-----------------------------------------------------------------------------------" << std::endl;
  std::cout << "[VER] Enter your selection: ";

  memset(local_buffer_agent, 0, BUFFERLEN);
  memset(local_buffer, 0, BUFFERLEN);
  fflush(stdin);
  fflush(stdout);
}

void send_exit_message(){
  size_t pt_size;
  byte* bytes_msg = get_exit_message(&pt_size);
  send_buffer(bytes_msg, pt_size);
  free(bytes_msg);
}

void verifier_exit(){
  printf("[VER] Verifier exiting. Shutdown...\n");
  send_exit_message();
  exit(0);
}

void send_agent_buffer(byte* buffer, size_t len){
  write(fd_sock_agent, buffer, len);  
}

byte* recv_buffer_agent(size_t* len){
  ssize_t n_read = read(fd_sock_agent, local_buffer_agent, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    printf("[VER] Invalid message header\n");
    verifier_exit();
  }

  size_t reply_size = *(size_t*)local_buffer_agent;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL) {
    printf("[VER] Message too large\n");
    verifier_exit();
  }

  n_read = read(fd_sock_agent, reply, reply_size);
  if(n_read != reply_size) {
    printf("[VER] Bad message size\n");
    verifier_exit();
  }

  *len = reply_size;
  return reply;
}

void recv_cert_chain_on_buffer_agent(
  unsigned char *sm_cert, unsigned char *root_cert, unsigned char *man_cert, unsigned char *lak_cert,
  size_t *sm_cert_len, size_t *root_cert_len, size_t *man_cert_len, size_t *lak_cert_len
) {
  // Read the 4 lengths
  read(fd_sock_agent, sm_cert_len, sizeof(size_t));
  read(fd_sock_agent, root_cert_len, sizeof(size_t));
  read(fd_sock_agent, man_cert_len, sizeof(size_t));
  read(fd_sock_agent, lak_cert_len, sizeof(size_t));

  // Read the certificates
  read(fd_sock_agent, (byte*) sm_cert, *sm_cert_len);
  read(fd_sock_agent, (byte*) root_cert, *root_cert_len);
  read(fd_sock_agent, (byte*) man_cert, *man_cert_len);
  read(fd_sock_agent, (byte*) lak_cert, *lak_cert_len);
}

void send_agent_exit_message() {
  memset(local_buffer_agent, 0, BUFFERLEN);
  local_buffer_agent[0] = 'q';
  local_buffer_agent[1] = '\0';

  send_agent_buffer(local_buffer_agent, 2);
}

void connect_to_agent_socket() {
  // Wait a couple of seconds in order to let the verifer connect to the enclave succesfully
  std::this_thread::sleep_for(std::chrono::seconds(2));

  // Now connect the verifier to the agent socket
  fd_sock_agent = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock_agent < 0){
    std::cout << "[VER] No socket\n" << std::endl;
    exit(-1);
  }

  server_addr_agent.sin_family = AF_INET;
  memcpy(&server_addr_agent.sin_addr.s_addr,server->h_addr,server->h_length);
  server_addr_agent.sin_port = htons(PORTNUM_AGENT);

  if (connect(fd_sock_agent, (struct sockaddr *)&server_addr_agent, sizeof(server_addr_agent)) < 0){
    std::cout << "[VER] Can't connect\n" << std::endl;
    exit(-1);
  }

  std::cout << "[VER] Connected to the agent socket!" << std::endl;
}

void connect_to_enclave_socket(char *argv[]) {
  // Start the enclave...  
  std::cout << "[VER] Connecting to the enclave..." << std::endl;
  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if(fd_sock < 0){
    printf("[VER] No socket\n");
    exit(-1);
  }
  server = gethostbyname(argv[1]);
  if(server == NULL) {
    printf("[VER] Can't get host\n");
    exit(-1);
  }
  server_addr.sin_family = AF_INET;
  memcpy(&server_addr.sin_addr.s_addr,server->h_addr,server->h_length);
  server_addr.sin_port = htons(PORTNUM);
  if(connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    printf("[VER] Can't connect\n");
    exit(-1);
  }
  printf("[VER] Connected to enclave host!\n");
}

std::array<unsigned char, NONCE_LEN> generate_nonce() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::array<unsigned char, 32> nonce;
    for (unsigned char &byte : nonce)
        byte = static_cast<unsigned char>(dis(gen));

    return nonce;
}

/* Request and verify the certificate chain */
bool request_cert_chain() {
  std::cout << "[VER] Requesting the certificates..." << std::endl;
  memset(local_buffer_agent, 0, BUFFERLEN);
  local_buffer_agent[0] = '1';
  local_buffer_agent[1] = '\0';
  send_agent_buffer(local_buffer_agent, 2);

  unsigned char sm_cert[MAX_CERT_LEN];
  unsigned char root_cert[MAX_CERT_LEN];
  unsigned char man_cert[MAX_CERT_LEN];
  unsigned char lak_cert[MAX_CERT_LEN];
  unsigned char lak_pk[LAK_PUB_LEN];
  size_t sm_cert_len, root_cert_len, man_cert_len, lak_cert_len;

  recv_cert_chain_on_buffer_agent(sm_cert, root_cert, man_cert, lak_cert, &sm_cert_len, &root_cert_len, &man_cert_len, &lak_cert_len);

  if(!verify_cert_chain(sm_cert, root_cert, man_cert, lak_cert, sm_cert_len, root_cert_len, man_cert_len, lak_cert_len))
    return false;

  if (!extract_lak_pub_from_x509_crt(lak_cert, lak_cert_len, lak_pk))
    return false;

  // NB: this UUID is for testing purposes!
  std::string uuid = get_test_uuid(db);
  if (uuid.empty())
    return false;

  std::string lak_pk_string = "";
  for (int i = 0; i < LAK_PUB_LEN; ++i)
    lak_pk_string += char_to_hex_str(lak_pk[i]);
  
  if (!save_trusted_lak_for_eapp(db, uuid, lak_pk_string))
    return false;

  return true;
}

void perform_runtime_attestation() {
  // If the LAK is not present, the attestation cannot be performed
  std::cout << "[VER] Performing run-time attestation..." << std::endl;
  std::string uuid = get_test_uuid(db);
  std::string lak_pub = get_lak_of_eapp(db, uuid);
  if (lak_pub.empty()) {
    std::cout << "[VER] Local Attestation Key not available. Verify the certificate chain as first step!" << std::endl;
    return;
  }

  // Copy the generated nonce after "2\0" 
  std::array<unsigned char, 32> nonce = generate_nonce();
  local_buffer_agent[0] = '2';
  local_buffer_agent[1] = '\0';
  std::copy(nonce.begin(), nonce.end(), local_buffer_agent + 2);

  #if RUNTIME_ATTESTATION_PERF_TEST
  auto start = std::chrono::high_resolution_clock::now();
  #endif

  // Send the request with the nonce
  size_t len;
  send_agent_buffer(local_buffer_agent, 34);
  byte* buffer = recv_buffer_agent(&len);

  #if RUNTIME_ATTESTATION_PERF_TEST
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end - start;
  std::cout << "[VER] Run-time attestation request elapsed time: " << duration.count() * 1000.0 << " ms" << std::endl;
  #endif

  std::string sm_ref_value = get_eapp_sm_hash(db, uuid);
  std::string encl_runtime_ref_value = get_eapp_rt_hash(db, uuid);
  std::string nonce_as_string = "";

  // If there is not an eapp run-time reference value, add to the DB
  if (encl_runtime_ref_value.empty()) {
    std::cout << "[VER] First EAPP run-time hash retrieved, adding measurement to the DB" << std::endl;
    encl_runtime_ref_value = get_enclave_rt_hash_from_report_buffer(buffer);
    save_eapp_rt_hash(db, uuid, encl_runtime_ref_value);
  }

  for (unsigned char c : nonce)
    nonce_as_string += char_to_hex_str(c);

  #if RUNTIME_ATTESTATION_PERF_TEST
  start = std::chrono::high_resolution_clock::now();
  #endif

  if (verifier_verify_runtime_report(
        buffer, encl_runtime_ref_value, sm_ref_value,
        lak_pub, nonce_as_string))
    std::cout << "[VER] " << "\033[1;32m" << "Verification succesful" << "\033[0m" << "!" << std::endl;
  else
    std::cout << "[VER] " << "\033[1;31m" << "Verification failed" << "\033[0m" << "!" << std::endl;

  #if RUNTIME_ATTESTATION_PERF_TEST
  end = std::chrono::high_resolution_clock::now();
  duration = end - start;
  std::cout << "[VER] Run-time report verification elapsed time: " << duration.count() * 1000.0 << " ms" << std::endl;
  #endif

  free(buffer);
}

/****************************************************************/
/****************************************************************/
/****************************************************************/

void send_buffer(byte* buffer, size_t len){
  write(fd_sock, &len, sizeof(size_t));
  write(fd_sock, buffer, len);  
}

byte* recv_buffer(size_t* len){
  ssize_t n_read = read(fd_sock, local_buffer, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    // Shutdown
    printf("[TC] Invalid message header\n");
    verifier_exit();
  }
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[TC] Message too large\n");
    verifier_exit();
  }
  n_read = read(fd_sock, reply, reply_size);
  if(n_read != reply_size){
    printf("[TC] Bad message size\n");
    // Shutdown
    verifier_exit();
  }

  *len = reply_size;
  return reply;
}

void recv_boot_time_report(int ignore_valid) {
  std::cout << "[VER] Requesting boot-time attestation report..." << std::endl;
  #if RUNTIME_ATTESTATION_PERF_TEST
  auto start = std::chrono::high_resolution_clock::now();
  #endif

  size_t report_size;
  byte* report_buffer = recv_buffer(&report_size);

  #if RUNTIME_ATTESTATION_PERF_TEST
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end - start;
  std::cout << "[VER] Boot-time attestation request elapsed time: " << duration.count() * 1000.0 << " ms" << std::endl;
  #endif

  bool res_boot = verifier_verify_boot_report(report_buffer, ignore_valid);
  free(report_buffer);
  if (!res_boot)
    verifier_exit();
}

/****************************************************************/
/****************************************************************/
/****************************************************************/

int main(int argc, char *argv[])
{
  int ignore_valid = 0;
  if(argc < 2) {
    printf("[VER] Usage %s hostname\n", argv[0]);
    exit(-1);
  }

  if(argc >= 3){
    if(strcmp(argv[2],"--ignore-valid") == 0){
      ignore_valid = 1;
    }
  }

  connect_to_enclave_socket(argv);  
  connect_to_agent_socket();

  recv_boot_time_report(ignore_valid);

  db = open_database();
  init_db(db, "127.0.0.1", PORTNUM_AGENT, get_sm_hash_as_string(), get_enclave_boot_hash_as_string());

  /* Send/recv messages */
  for(;;){
    print_menu();
    fgets((char*)local_buffer_agent, BUFFERLEN-1, stdin);
    std::cout << std::endl;

    if (!(local_buffer_agent[1] == '\0' || local_buffer_agent[1] == '\n')) {
      std::cout << "[VER] Wrong command format: it must be 1 character identifier" << std::endl;
      continue;
    }

    switch (local_buffer_agent[0]) {
      case '1':
        request_cert_chain();
        break;
      case '2':
        perform_runtime_attestation();
        break;
      case 'q':
        std::cout << "[VER] Disconnecting from the agent socket..." << std::endl;
        send_agent_exit_message();
        close_database(db);
        close(fd_sock_agent);
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::cout << "[VER] Disconnecting from the TA socket..." << std::endl;
        send_exit_message();
        close(fd_sock);

        exit(0);
        break;    
      default:
        std::cout << "[VER] Invalid command inserted!" << std::endl;
        break;
    }      
  }

  return 0;
}
