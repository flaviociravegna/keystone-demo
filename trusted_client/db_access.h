#include <string>
#include "sqlite-amalgamation-3420000/sqlite3.h"


struct EappRegistration {
    std::string UUID;
    std::string AgentIP;
    int AgentPort;
    std::string HashSM;
    std::string HashEappBoot;
    std::string HashEappRt;

    // Constructor
    EappRegistration(const std::string& uuid, const std::string& agentIP, int agentPort,
         const std::string& hashSM, const std::string& hashEappBoot, const std::string& hashEappRt)
            : UUID(uuid), AgentIP(agentIP), AgentPort(agentPort), 
            HashSM(hashSM), HashEappBoot(hashEappBoot), HashEappRt(hashEappRt) {}
};

sqlite3* open_database();
void init_db(sqlite3* db, std::string agent_ip, int agent_port, std::string sm_hash, std::string enclave_hash_boot);
void close_database(sqlite3* db);
bool execute_query(sqlite3* db, const char* query);

std::string get_all_entries(sqlite3* db);
std::string get_lak_of_eapp(sqlite3 *db, std::string uuid);
std::string get_eapp_boot_hash(sqlite3* db, std::string uuid);
std::string get_eapp_rt_hash(sqlite3* db, std::string uuid);
std::string get_eapp_sm_hash(sqlite3* db, std::string uuid);
std::string get_test_uuid(sqlite3 *db);

bool save_trusted_lak_for_eapp(sqlite3 *db, std::string uuid, std::string lak);
bool save_eapp_rt_hash(sqlite3 *db, std::string uuid, std::string rt_hash);