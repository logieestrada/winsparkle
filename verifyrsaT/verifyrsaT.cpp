// verifyrsaT.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>

#include "publickey.h"
#include "verifyrsa.h"

using namespace std;

const string sig = "C:\\Users\\edwin\\AppData\\Local\\Temp\\Update-0bf3e03f-6a12-40e9-b96f-8b086eca5860\\LogiCameraSettings_2.1.115.0.exe.sig";
const string inFile = "C:\\Users\\edwin\\AppData\\Local\\Temp\\Update-0bf3e03f-6a12-40e9-b96f-8b086eca5860\\LogiCameraSettings_2.1.115.0.exe";

int _tmain(int argc, _TCHAR* argv[])
{
	std::vector<uint8_t> message, signa;
	ifstream is(inFile.c_str(), ios::binary);
	ifstream issig(sig.c_str(), ios::binary);

	if (issig)
	{
		issig.seekg(0, ios::end);
		int len = issig.tellg();
		issig.seekg(0);

		signa.resize(len);
		issig.read(reinterpret_cast<char*>(signa.data()), len);
		issig.close();
	}

	if (is)
	{
		is.seekg(0, ios::end);
		int len = is.tellg();
		is.seekg(0);

		message.resize(len);
		is.read(reinterpret_cast<char*>(message.data()), len);
		is.close();
	}

	bool verified = verifyRSASignature(publicKey.data(), publicKey.length(), reinterpret_cast<unsigned char*>(message.data()), message.size(), reinterpret_cast<unsigned char*>(signa.data()), signa.size());

	cout << (verified ? "Ok" : "fail");

	return 0;
}

