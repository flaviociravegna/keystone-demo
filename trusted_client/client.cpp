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


#define PORTNUM_AGENT 8068
#define PORTNUM 8067
int fd_sock, fd_sock_agent;
struct sockaddr_in server_addr, server_addr_agent;
struct hostent *server;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN], local_buffer_agent[BUFFERLEN];


void send_buffer(byte* buffer, size_t len){
  write(fd_sock, &len, sizeof(size_t));
  write(fd_sock, buffer, len);  
}

void send_agent_buffer(byte* buffer, size_t len){
  write(fd_sock_agent, &len, sizeof(size_t));
  write(fd_sock_agent, buffer, len);  
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

byte* recv_buffer_agent(size_t* len){
  ssize_t n_read = read(fd_sock_agent, local_buffer_agent, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    // Shutdown
    printf("[TC] Invalid message header\n");
    trusted_client_exit();
  }
  size_t reply_size = *(size_t*)local_buffer_agent;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[TC] Message too large\n");
    trusted_client_exit();
  }
  n_read = read(fd_sock_agent, reply, reply_size);
  if(n_read != reply_size){
    printf("[TC] Bad message size\n");
    // Shutdown
    trusted_client_exit();
  }

  *len = reply_size;
  return reply;
}

void do_something() {
  sqlite3 *db = open_database();
  init_db(db, "127.0.0.1", PORTNUM_AGENT, get_sm_hash_as_string(), get_enclave_boot_hash_as_string());

  std::string s = get_all_entries(db);

  /*
  std::stringstream ss(s);

  std::string segment;
  std::vector<std::string> seglist;

  while(std::getline(ss, segment, ';'))
    seglist.push_back(segment);

  for (int i = 0; i < seglist.size(); i++)
    std::cout << "DB entry: " << seglist.at(i) << std::endl;*/
      
  close_database(db);
}

int main(int argc, char *argv[])
{
  int ignore_valid = 0;
  if(argc < 2) {
    printf("Usage %s hostname\n", argv[0]);
    exit(-1);
  }

  if(argc >= 3){
    if(strcmp(argv[2],"--ignore-valid") == 0){
      ignore_valid =1;
    }
  }
  
  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if(fd_sock < 0){
    printf("No socket\n");
    exit(-1);
  }
  server = gethostbyname(argv[1]);
  if(server == NULL) {
    printf("Can't get host\n");
    exit(-1);
  }
  server_addr.sin_family = AF_INET;
  memcpy(&server_addr.sin_addr.s_addr,server->h_addr,server->h_length);
  server_addr.sin_port = htons(PORTNUM);
  if(connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    printf("Can't connect\n");
    exit(-1);
  }

  printf("[TC] Connected to enclave host!\n");

  /**************************** Agent socket ********************************/

  // Connect the verifier to the agent socket
  fd_sock_agent = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock_agent < 0){
    printf("No socket\n");
    exit(-1);
  }

  server_addr_agent.sin_family = AF_INET;
  memcpy(&server_addr_agent.sin_addr.s_addr,server->h_addr,server->h_length);
  server_addr_agent.sin_port = htons(PORTNUM_AGENT);

  if (connect(fd_sock_agent, (struct sockaddr *)&server_addr_agent, sizeof(server_addr_agent)) < 0){
    printf("Can't connect\n");
    exit(-1);
  }

  printf("[TC] Connected to agent socket!\n");

  /****************************************************************************/

  /* Establish channel */
  trusted_client_init();
  
  size_t report_size;
  byte* report_buffer = recv_buffer(&report_size);
  trusted_client_get_report(report_buffer, ignore_valid);
  free(report_buffer);

  /* Send pubkey */
  size_t pubkey_size;
  byte* pubkey = trusted_client_pubkey(&pubkey_size);
  send_buffer(pubkey, pubkey_size);

  /*
  send_agent_buffer(local_buffer_agent, 2);
  byte* cert_bytes = recv_buffer_agent(&reply_size);
  std::string certificate(reinterpret_cast<char*>(cert_bytes), reply_size);
  std::cout << "Received certificate: " << certificate << std::endl;
  */

  /* Request and verify the certificate chain */
  std::cout << "[TC] Contacting agent for certs..." << std::endl;
  size_t reply_size;
  local_buffer_agent[0] = '1';
  local_buffer_agent[1] = '\0';
  send_agent_buffer(local_buffer_agent, 2);
  byte* cert_bytes = recv_buffer_agent(&reply_size);
  //verify_cert_chain();
  
  /* Send/recv messages */
  for(;;){
    printf("Either type message for remote word count, or q to quit\n> ");

    memset(local_buffer, 0, BUFFERLEN);
    fgets((char*)local_buffer, BUFFERLEN-1, stdin);
    printf("\n");

    /* Handle quit */
    if(local_buffer[0] == 'q' && (local_buffer[1] == '\0' || local_buffer[1] == '\n')){
      send_exit_message();
      close(fd_sock);
      exit(0);
    }
    else{
      if (local_buffer[0] == 'a') {
        do_something();
        send_agent_buffer(local_buffer, 5);
      } else {
        send_wc_message((char*)local_buffer);
        size_t reply_size;
        byte* reply = recv_buffer(&reply_size);
        trusted_client_read_reply(reply, reply_size);
        free(reply);
      }
    }
  }
  return 0;
}
