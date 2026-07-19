#include "../include/const.h"
#include "../utility/Hash.cpp"
#include "DTOs.h"

class UserInfoManager{

private: 

    status outcome;
    vector<UserInfo> clientListInformation;

    int findUser(const string username){
        
        int index = -1; 
        for (int i = 0; i < clientListInformation.size(); i++){
            if(clientListInformation[i].username == username){
                index = i; 
                break;
            }
        }

        return index;
    }

public: 

    UserInfoManager(){

        outcome = status::OK;
        
        std::ifstream file(USER_CREDENTIALS_PATH);
        
        if (!file.is_open()) {
            printf("ERROR WHEN OPENING JSON FILE AT %s\n", USER_CREDENTIALS_PATH);
            outcome = status::ERROR;
            return;
        }

        json j;
        try {
            file >> j; // Parsing
        } catch (const json::parse_error& e) {
            printf("ERROR WHEN PARSING JSON FILE: %s\n", e.what());
            outcome = status::ERROR;
            return;
        }

        clientListInformation = j.get<std::vector<UserInfo>>();
    }

    bool isValid(){
        return (outcome == status::OK);
    }

    bool checkCredentials(const string username, const string psw){

        int index = findUser(username);
        if(index == -1){
            printf("Username %s not found", username.c_str());
            return false; 
        }

        Hash hashManager; 
        string salted_psw = clientListInformation[index].salt + psw;
        char* hashed_pwd = (char*)hashManager.calculateHash(salted_psw.c_str());

        char string_hash[65];
        hashManager.hashToString((unsigned char*)hashed_pwd,string_hash);
        string_hash[64] = '\0';

        bool valid_password = clientListInformation[index].password == string_hash;
        return valid_password; 
    }

    TimestampInfo getTimestamps(const char* username){
        int index = findUser(username);
        
        TimestampInfo timestamps{clientListInformation[index].timestamps_remaining, clientListInformation[index].timestamps_consumed};
        return timestamps;
    } 

    void printa(){
        for (int i = 0; i < clientListInformation.size(); i++){
            UserInfo u = clientListInformation[i];
            printf("\n{\nuser: %s\nsale: %s\npwd: %s\ntime_r: %d\ntime_c: %d\n}\n",u.username.c_str(),u.salt.c_str(),u.password.c_str(),u.timestamps_remaining,u.timestamps_consumed);
        }
    }

};