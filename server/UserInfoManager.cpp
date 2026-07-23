#ifndef UINFOMNG
#define UINFOMNG

#include "../include/const.h"
#include "../utility/Hash.cpp"
#include "../utility/DTOs.h"

class UserInfoManager{

private: 

    status outcome;
    vector<UserInfo> clientListInformation;
    mutex mtx;

public: 

    int findUser(const string username){
        
        int index = -1; 
        int num_users = clientListInformation.size();
        for (int i = 0; i < num_users; i++){
            if(clientListInformation[i].username == username){
                index = i; 
                break;
            }
        }

        return index;
    }

    UserInfoManager(){

        outcome = status::OK;
        
        std::ifstream file(USER_CREDENTIALS_PATH);
        
        if (!file.is_open()) {
            printf(ERROR_MESS "CAN'T OPEN JSON FILE AT %s\n", USER_CREDENTIALS_PATH);
            outcome = status::ERROR;
            return;
        }

        json j;
        try {
            file >> j; // Parsing
        } catch (const json::parse_error& e) {
            printf(ERROR_MESS "CAN'T PARSE JSON FILE: %s\n", e.what());
            outcome = status::ERROR;
            return;
        }

        clientListInformation = j.get<std::vector<UserInfo>>();
    }

    status saveToFile(){

        lock_guard<mutex> lock(mtx);

        std::ofstream file(USER_CREDENTIALS_PATH);

        if(!file.is_open()){
            printf(ERROR_MESS "Error while opening %s file\n", USER_CREDENTIALS_PATH);
            return status::ERROR;
        }

        json j = clientListInformation;

        try {
            file << j.dump(4);
        } catch (const json::exception& e) {
            printf(ERROR_MESS "CAN'T SERIALIZE TO JSON: %s\n", e.what());
            return status::ERROR;
        }

        file.close();

        return status::OK;
    }

    bool isValid(){
        return (outcome == status::OK);
    }

    bool checkCredentials(const char* usr_ptr, const char* psw_ptr){

        const string username(usr_ptr);
        const string psw(psw_ptr);

        int index = findUser(username);
        if(index == -1){
            printf(WARNING_MESS "Username \"%s\" not found\n", username.c_str());
            return false; 
        }
        
        Hash hashManager; 
        string salted_psw = clientListInformation[index].salt + psw;
        unsigned char hashed_pwd[HASH_SIZE];

        hashManager.calculateHash(salted_psw.c_str(), salted_psw.length() ,hashed_pwd);

        char string_hash[HASH_SIZE*2 + 1];
        hashManager.hashToString(hashed_pwd,string_hash);
        string_hash[HASH_SIZE*2] = '\0';

        int ret = CRYPTO_memcmp(clientListInformation[index].password.data(), string_hash, HASH_SIZE * 2);
        bool valid_password = (ret == 0);

        return valid_password; 
    }

    TimestampInfo getTimestamps(const unsigned int index){
        
        TimestampInfo timestamps{clientListInformation[index].timestamps_remaining, clientListInformation[index].timestamps_consumed};
        return timestamps;
    } 

    void printData(){
        int num_users = clientListInformation.size();
        for (int i = 0; i < num_users; i++){
            UserInfo u = clientListInformation[i];
            printf("\n{\nuser: %s\nsale: %s\npwd: %s\ntime_r: %d\ntime_c: %d\n}\n",u.username.c_str(),u.salt.c_str(),u.password.c_str(),u.timestamps_remaining,u.timestamps_consumed);
        }
    }

    status consumeTimestamp(int index){

        if(index < 0 || index >= (int)clientListInformation.size()){
            printf(ERROR_MESS "Invalid index\n");
            return status::ERROR;
        }

        UserInfo* user = &clientListInformation[index];
        if(user->timestamps_remaining == 0){
            printf(WARNING_MESS "User \"%s\" has no timestamps left\n", user->username.c_str());
            return status::INVALID;
        }

        user->timestamps_remaining--; 
        user->timestamps_consumed++;

        saveToFile();

        //printData();
        return status::OK;
    }

};
#endif