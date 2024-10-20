#pragma warning(disable:4996)

#include <iterator>
#include <vector>
#include <iostream>
#include <wchar.h>
#include <cstdlib>

#ifdef _WIN32
#include <tchar.h>
#else
#include <cstdio>
#include "reader/tchar.h"
#endif

# include "cades.h"

using namespace std;

#include "../samples_util.h"

/*
Пример показывает в отдельном окне список усовершенствованных подписей. Предварительно подписи 
должны быть созданы и сохранены в файл sign.dat (примеры LowlevelSignCades, LowlevelSignCadesBes). 
sign.dat должен находится в каталоге приложения.
*/

int main(void)
{
    vector<unsigned char> message;
    // Читаем подпись из файла
    if (ReadFileToVector("sign.dat", message))
    {
        cout << "Reading signature from file \"sign.dat\" failed" << endl;
        return -1;
    }

    if (message.empty())
    {
        cout << "File \"sign.dat\" is empty" << endl;
        return -1;
    }

    // Открываем дескриптор сообщения
    HCRYPTMSG hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
    if (!hMsg)
    {
	cout << "CryptMsgOpenToDecode() failed" << endl;
	return -1;
    }

    // Заполняем прочитанной подписью криптографическое сообщение
    if (!CryptMsgUpdate(hMsg, &message[0], (unsigned long)message.size(), 1))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgUpdate() failed" << endl;
	return -1;
    }

    // Отображаем окно со списком подписей, содержащихся в сообщении
    if (!CadesMsgUIDisplaySignatures(hMsg, 0, L"Подпись"))
    {
	cout << "CadesUIDisplaySignature() failed." << endl;
	return -1;
    }

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg))
    {
	cout << "CryptMsgClose() failed" << endl;
	return -1;
    }

    return 0;
}
