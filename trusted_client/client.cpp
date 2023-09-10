#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <unistd.h>
#include "trusted_client.h"
#include "client.h"
#include "db_access.h"
extern "C" {
    #include "cert_verifier.h"
}

#include <vector>
#include <sstream>

#include <thread>
#include <chrono>

#define PORTNUM_AGENT 8068
#define PORTNUM 8067
sqlite3 *db;
int fd_sock, fd_sock_agent;
struct sockaddr_in server_addr, server_addr_agent;
struct hostent *server;
bool is_key = false;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN], local_buffer_agent[BUFFERLEN];

/****************************************************************/
/*********************** NEW FUNCTIONS **************************/
/****************************************************************/

void send_agent_buffer(byte* buffer, size_t len){
  write(fd_sock_agent, &len, sizeof(size_t));
  write(fd_sock_agent, buffer, len);  
}

byte* recv_buffer_agent(size_t* len){
  ssize_t n_read = read(fd_sock_agent, local_buffer_agent, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    // Shutdown
    printf("[VER] Invalid message header\n");
    trusted_client_exit();
  }
  size_t reply_size = *(size_t*)local_buffer_agent;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[VER] Message too large\n");
    trusted_client_exit();
  }
  n_read = read(fd_sock_agent, reply, reply_size);
  if(n_read != reply_size){
    printf("[VER] Bad message size\n");
    // Shutdown
    trusted_client_exit();
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

  //printf("[VER] read lengths (sm: %d, root: %d, man: %d, lak: %d)\n", *sm_cert_len, *root_cert_len, *man_cert_len, *lak_cert_len);

  // Read the certificates
  read(fd_sock_agent, (byte*) sm_cert, *sm_cert_len);
  read(fd_sock_agent, (byte*) root_cert, *root_cert_len);
  read(fd_sock_agent, (byte*) man_cert, *man_cert_len);
  read(fd_sock_agent, (byte*) lak_cert, *lak_cert_len);
}

void do_something() {
  db = open_database();
  init_db(db, "127.0.0.1", PORTNUM_AGENT, get_sm_hash_as_string(), get_enclave_boot_hash_as_string());

  std::string s = get_all_entries(db);
  //close_database(db);
}

void connect_to_agent_socket() {
  std::cout << "[VER] Connecting to the agent...\n" << std::endl;

  // Connect the verifier to the agent socket
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

  std::cout << "[VER] Connected to the agent socket!\n" << std::endl;
}

/* Request and verify the certificate chain */
bool request_cert_chain() {
  std::cout << "[VER] Requesting the certificates..." << std::endl;
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

  std::string lak_pk_string = std::string(lak_pk, lak_pk + LAK_PUB_LEN);
  if (!save_trusted_lak_for_eapp(db, uuid, lak_pk_string))
    return false;

  return true;
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
    trusted_client_exit();
  }
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[TC] Message too large\n");
    trusted_client_exit();
  }
  n_read = read(fd_sock, reply, reply_size);
  if(n_read != reply_size){
    printf("[TC] Bad message size\n");
    // Shutdown
    trusted_client_exit();
  }

  *len = reply_size;
  return reply;
}

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

  // Start the enclave...  
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
  
  connect_to_agent_socket();

  /************************* Establish channel *************************/

  trusted_client_init();
  
  size_t report_size;
  byte* report_buffer = recv_buffer(&report_size);
  trusted_client_get_report(report_buffer, ignore_valid);
  free(report_buffer);

  /* Send pubkey */
  size_t pubkey_size;
  byte* pubkey = trusted_client_pubkey(&pubkey_size);
  is_key = true;
  send_buffer(pubkey, pubkey_size);

  /****************************************************************************/
  /****************************************************************************/

  db = open_database();
  init_db(db, "127.0.0.1", PORTNUM_AGENT, get_sm_hash_as_string(), get_enclave_boot_hash_as_string());

  /* Send/recv messages */
  for(;;){
    printf("\n[VER] Select the operation [1: Request Certificate Chain, 2: Perform Runtime Attestation, 3: Word Count, q: Quit]:\n> ");
    memset(local_buffer_agent, 0, BUFFERLEN);
    memset(local_buffer, 0, BUFFERLEN);
    fgets((char*)local_buffer_agent, BUFFERLEN-1, stdin);
    printf("\n");

    if(local_buffer_agent[0] == '3'){
      printf("[VER] Insert the words to count: ");
      fgets((char*)local_buffer, BUFFERLEN-1, stdin);
      printf("\n");

      send_wc_message((char*)local_buffer);
      size_t reply_size;
      byte* reply = recv_buffer(&reply_size);
      trusted_client_read_reply(reply, reply_size);
      free(reply);
    }

    /* Handle quit */
    if(local_buffer_agent[0] == 'q' && (local_buffer_agent[1] == '\0' || local_buffer_agent[1] == '\n')) {
      std::cout << "[VER] Disconnecting from the TA socket..." << std::endl;
      memset(local_buffer, 0, BUFFERLEN);
      fflush(stdin);
      fflush(stdout);
      std::this_thread::sleep_for(std::chrono::seconds(2));

      std::cout << "[VER] Disconnecting from the agent socket..." << std::endl;
      close_database(db);
      close(fd_sock_agent);

      exit(0);
    } else if (local_buffer_agent[0] == '1' && (local_buffer_agent[1] == '\0' || local_buffer_agent[1] == '\n')) {
      request_cert_chain();
    } else if (local_buffer_agent[0] == '2' && (local_buffer_agent[1] == '\0' || local_buffer_agent[1] == '\n')) {
      do_something();
    } else
      std::cout << "[VER] Invalid command inserted!" << std::endl;
  }
  return 0;
}
