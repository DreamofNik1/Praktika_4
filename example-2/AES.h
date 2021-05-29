#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include "cryptopp/modes.h"
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
using namespace CryptoPP;

class AlgAES
{
private:
  string filePath_in;
  string filePath_out;
  string parol;
  string filePath_Iv;
  string salt = "soldgfdghvcxvxchggfhgfldasd";
public:
  AlgAES() = delete;
  AlgAES(const string& filePath_in, const string& filePath_out, const string& Pass);
  AlgAES(const string& filePath_in, const string& filePath_out, const string& Pass, const string & iv);
  void encryptAES (AlgAES enc);
  void decryptAES (AlgAES dec);
};
