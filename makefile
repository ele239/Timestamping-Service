all: server client

server: server.cpp server/ServerConnection.cpp server/UserInfoManager.cpp utility/CryptoSym.cpp server/ServerAsym.cpp server/ResponseManager.cpp utility/CryptoAsym.cpp utility/Connection.cpp utility/CryptoSym.cpp utility/DTOs.h utility/Hash.cpp utility/Mess.h include/all.h include/const.h
	g++ -Wall -std=c++20 server.cpp -o sv -lcrypto

client: client.cpp client/ClientConnection.cpp client/ClientAsym.cpp client/SessionManager.cpp utility/Connection.cpp utility/CryptoSym.cpp utility/CryptoAsym.cpp utility/Hash.cpp utility/DTOs.h utility/Mess.h  include/all.h include/const.h
	g++ -Wall -std=c++20 client.cpp -o cl -lcrypto

cl_run:
	./cl < cl_input.txt

clean:
	rm -f sv cl