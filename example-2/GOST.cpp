#include "GOST.h"
AlgGost::AlgGost(const string& filePath_in, const string& filePath_out, const string& pass)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->parol = pass;
}

AlgGost::AlgGost(const string& filePath_in, const string& filePath_out, const string& pass, const string & iv)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->parol = pass;
    this->filePath_Iv = iv;
}

void AlgGost::encryptGost (AlgGost enc)
{
    //Генерация ключа
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)enc.parol.data(), enc.parol.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Генерация вектора инициализации
    AutoSeededRandomPool prng;
    byte iv[GOST::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    //Вектор инициализации записывается в файл
    ofstream v_IV(string(enc.filePath_out + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, GOST::BLOCKSIZE);
    v_IV.close();

    cout << "Файл \"IV\" c вектором инициализации успешно создан.\nПуть: " << enc.filePath_out << ".iv" << endl;

    //Запись шифрования в файл
    CBC_Mode<GOST>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filePath_in.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.filePath_out.c_str())));
    cout << "Шифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << enc.filePath_out << endl;
}

void AlgGost::decryptGost (AlgGost dec)
{
    //Генерация ключа (пароль тот же)
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)dec.parol.data(), parol.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Вектор инициализации из файла, который формируется при шифровании
    byte iv[GOST::BLOCKSIZE];
    ifstream v_IV(dec.filePath_Iv.c_str(), ios::in | ios::binary);
    //Проверки файла с вектором инициализации на ошибки
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), GOST::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw string ("Ошибка: Файл \"IV\" (с вектором инициализации) не открыт");
        v_IV.close();
    } else {
        throw string ("Ошибка: Файл \"IV\" (с вектором инициализации) некорректный");
        v_IV.close();
    }
    //Расшифрование
    CBC_Mode<GOST>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filePath_in.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.filePath_out.c_str())));
    cout << "Расшифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << dec.filePath_out << endl;
}
