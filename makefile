all: server client

server: server.cpp server/ServerConnection.cpp server/UserInfoManager.cpp utility/CryptoSym.cpp server/ServerAsym.cpp
	g++ -Wall -std=c++20 server.cpp -o sv -lcrypto

client: client.cpp client/ClientConnection.cpp client/ClientAsym.cpp
	g++ -std=c++20 client.cpp -o cl -lcrypto

clean:
	rm -f sv cl