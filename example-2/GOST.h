#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/gost.h>
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

class AlgGost
{
private:
  string filePath_in;
  string filePath_out;
  string filePath_Iv;
  string parol;
  string salt = "solurahelszxytrgvbcvbsewqe";
public:
  AlgGost() = delete;
  AlgGost(const string& filePath_in, const string& filePath_out, const string& pass);
  AlgGost(const string& filePath_in, const string& filePath_out, const string& pass, const string & iv);
  void encryptGost (AlgGost enc);
  void decryptGost (AlgGost dec);
};
