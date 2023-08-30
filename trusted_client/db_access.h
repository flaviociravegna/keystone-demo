#include <string>
#include "sqlite-amalgamation-3420000/sqlite3.h"


struct EappRegistration {
    std::string UUID;
    std::string AgentIP;
    int AgentPort;

    // Constructor
    EappRegistration(const std::string& uuid, const std::string& agentIp, int agentPort)
        : UUID(uuid), AgentIP(agentIp), AgentPort(agentPort) {}
};

sqlite3* open_database();
bool execute_query(sqlite3* db, const char* query);
std::string get_all_entries(sqlite3* db);
void init_db(sqlite3* db, std::string agent_ip, int agent_port);
void close_database(sqlite3* db);