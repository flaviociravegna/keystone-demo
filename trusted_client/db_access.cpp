#include <iostream>
#include <uuid/uuid.h>
#include "db_access.h"

/* From the SQLITE documentation: If the path begins with a '/' character, then it is interpreted as an absolute path.
If the path does not begin with a '/' then the path is interpreted as a relative path */
std::string db_path = "db/verifier.db";

/*********************** Support Functions *****************************/

// Callback function to append each row to a string with ',' between fields and ';' between rows
// Example row format: <field_1_name:field_2_value, ... , field_N_name:field_N_value;>
int append_row_callback(void* data, int argc, char* argv[], char* colNames[]) {
    std::string* resultString = static_cast<std::string*>(data);

    for (int i = 0; i < argc; ++i) {
        *resultString += colNames[i];
        *resultString += ": ";
        *resultString += (argv[i] ? argv[i] : "NULL");
        
        // Add ',' between fields except for the last one
        if (i < argc - 1)
            *resultString += ",";
    }

    *resultString += ";";
    return 0; // Return 0 to continue processing more rows
}

std::string generateUUID() {
    uuid_t uuid;
    uuid_generate(uuid);

    char uuidStr[37]; // UUIDs are 36 characters long plus a null-terminator
    uuid_unparse_lower(uuid, uuidStr); // convert the UUID from binary representation to a string

    return std::string(uuidStr);
}

/***********************************************************************/

sqlite3* open_database() {
    sqlite3* db;
    const char* URI = (std::string("file:") + db_path).c_str();
    int res = sqlite3_open_v2(URI, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, nullptr);

    if (res != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    } else 
        std::cout << "DB <" << db_path << "> opened" << std::endl;
    
    return db;
}

void close_database(sqlite3* db) {
    sqlite3_close(db);
    std::cout << "DB <" << db_path << "> closed" << std::endl;
}

bool execute_query(sqlite3* db, const char* query) {
    char* errMsg = nullptr;
    
    if (sqlite3_exec(db, query, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    
    return true;
}

// Function to retrieve all entries from the "Temp" table and return as a C++ string
std::string get_all_entries(sqlite3* db) {
    std::string result;

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, "SELECT * FROM EAPPS;", append_row_callback, &result, &errMsg);

    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }

    return result;
}

void init_db(sqlite3* db, std::string agent_ip, int agent_port) {
    execute_query(db, "CREATE TABLE IF NOT EXISTS EAPPS (UUID TEXT PRIMARY KEY, AgentIP TEXT NOT NULL, AgentPort INTEGER NOT NULL);");

    for (int i = 0; i < 10; i++) {
        EappRegistration registration(generateUUID(), agent_ip, agent_port);
        execute_query(db, "INSERT INTO EAPPS (UUID, AgentIP, AgentPort) VALUES ("
            + registration.UUID + ", " 
            + registration.AgentIP + ", " 
            + registration.AgentPort + ")"
        );
    }
}