#include "AES.h"
#include "GOST.h"

int main ()
{
    bool isTrue = true;
    string mode;
    string f_in, f_out,f_iv,password;
    cout << "Добро пожаловать в программу для зашифрования и расшифрования." << endl;
    cout << "Режимы работы:" << endl;
    cout << " encryptGOST - шифрование по алгоритму \"GOST\"" << endl;
    cout << " encryptAES - шифрование по алгоритму  \"AES\"" << endl;
    cout << " decryptGOST - расшифрование по алгоритму \"GOST\"" << endl;
    cout << " decryptAES - расшифрование по алгоритму \"AES\"" << endl;
    do {
        cout << "Выберете режим: ";
        cin >> mode;
        if (mode == "encryptGOST") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, для сохранения результата: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgGost enc(f_in,f_out,password);
                enc.encryptGost(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "encryptAES") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, для сохранения результата: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgAES enc(f_in,f_out,password);
                enc.encryptAES(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "decryptGOST") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, для сохранения  результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgGost dec(f_in,f_out,password,f_iv);
                dec.decryptGost(dec);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "decryptAES") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, для сохранения результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgAES dec(f_in,f_out, password, f_iv );
                dec.decryptAES(dec);
            } catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "exit") {
            cout << "Завершение работы." << endl;
            isTrue = false;
            break;
        }
    } while (isTrue != false);

    return 0;
}
