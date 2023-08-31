#include <iostream>
#include <random>
//#include <boost/uuid/uuid.hpp>
//#include <boost/uuid/uuid_generators.hpp>
//#include <boost/uuid/uuid_io.hpp>
//#include <uuid.h>
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

// This is temporary: a better solution should be to use an external library
std::string generateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::string uuid;
    const char* hex_chars = "0123456789abcdef";

    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            uuid += '-';
        else if (i == 14)
            uuid += '4'; // Version 4 UUID
        else if (i == 19)
            uuid += hex_chars[(dis(gen) & 0x3) | 0x8]; // Variant (RFC4122)
        else
            uuid += hex_chars[dis(gen)];
    }

    return uuid;
}

std::string get_by_criteria(sqlite3* db, std::string uuid, std::string column_name) {
    std::string result;
    std::string sql = "SELECT " + column_name + " FROM EAPPS WHERE UUID=?";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Error preparing SQL statement: " << sqlite3_errmsg(db) << std::endl;
        return result;
    }

    // Bind the UUID parameter to the prepared statement
    rc = sqlite3_bind_text(stmt, 1, uuid.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        std::cerr << "Error binding parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return result;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* value = sqlite3_column_text(stmt, 0);
        if (value)
            result = reinterpret_cast<const char*>(value);
    } else if (rc != SQLITE_DONE)
        std::cerr << "Error executing SQL statement: " << sqlite3_errmsg(db) << std::endl;

    sqlite3_finalize(stmt);
    return result;
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

void init_db(sqlite3* db, std::string agent_ip, int agent_port, std::string sm_hash, std::string enclave_hash_boot) {
    std::string sql_create = "CREATE TABLE IF NOT EXISTS EAPPS (UUID TEXT PRIMARY KEY, AgentIP TEXT NOT NULL, AgentPort INTEGER NOT NULL, HashSM TEXT NOT NULL, HashEappBoot TEXT NOT NULL, HashEappRt TEXT);";
    execute_query(db, sql_create.c_str());
    
    for (int i = 0; i < 10; i++) {
        EappRegistration registration(generateUUID(), agent_ip, agent_port, sm_hash, enclave_hash_boot, "");
        std::string sql_insert = "INSERT INTO EAPPS (UUID, AgentIP, AgentPort, HashSM, HashEappBoot, HashEappRt) VALUES ('" +
                  registration.UUID + "', '" +
                  registration.AgentIP + "', " +
                  std::to_string(registration.AgentPort) + ", '" +
                  registration.HashSM + "', '" +
                  registration.HashEappBoot + "', '" +
                  registration.HashEappRt + "');";
        execute_query(db, sql_insert.c_str());
    }

    std::cout << "Entries inserted succesfully in the database" << std::endl;
}

std::string get_eapp_boot_hash(sqlite3* db, std::string uuid) {
    return get_by_criteria(db, uuid, "HashEappBoot");
}

std::string get_eapp_rt_hash(sqlite3* db, std::string uuid) {
    return get_by_criteria(db, uuid, "HashEappRt");
}