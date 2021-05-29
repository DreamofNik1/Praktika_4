#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int main ()
{
    
 CryptoPP::SHA384 hash; // создание хэш-объекта

 cout <<"Name: " <AlgorithmName() << endl; // Имя алгоритма
 cout << "Diget size:" <DigestSize() << endl; //размер хэша
 cout << "Block size:" <BlockSize() << endl; // размер внутреннего Блока
 fstream file;
 string path = "/home/student/my_cplusplus_programs/crypto/hash.txt"; // Путь до файла
 string str_message, file_contents;
 file.open(path);
    if(!file.is_open()) {
 cout << "Ошибка: файл не открыт" << endl;
        return 1;
    }
    while(true) {
        getline(file,str_message);
        if (file.fail()) //наличие файла
            break;
 file_contents += str_message;
    }
 cout << "File_contents: " << file_contents << endl; // содержимое файла

 vector<byte> digest (hash.DigestSize()); // создаем нужный размер

 hash.Update(reinterpret_cast <const byte*> (file_contents.data()),file_contents.size()); // считаем хэш 
 hash.Final(digest.data()); // получаем результат

 cout << "Digest HEX format: ";
    CryptoPP::StringSource(digest.data(),digest.size(),true, new  CryptoPP::HexEncoder(new  CryptoPP::FileSink(cout))); // выводим хэш в формате "hex"
 cout << endl;
    return 0;
}
