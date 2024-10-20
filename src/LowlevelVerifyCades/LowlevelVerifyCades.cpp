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

#include "cades.h"

using namespace std;

#include "../samples_util.h"

/*
Пример проверки подписи CADES_X_LONG_TYPE_1 с помощью низкоуровневых функций
КриптоПро ЭЦП SDK. Пример проверяет присоединенную подпись. Результат проверки
будет выведен на консоль. Подпись должна быть предварительно сохранена в файл
sign.dat (примеры LowlevelSignCades, LowlevelSignCadesBes). sign.dat должен находится
в каталоге приложения. Также в хранилище сертификатов необходимо наличие сертификата 
службы штампов времени.
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
    
    // Открываем дескриптор сообщения для декодирования для проверки усовершенствованной подписи
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

    PCADES_VERIFICATION_INFO pInfo = 0;
    // Проверяем подпись сообщения
    if (!CadesMsgVerifySignature(hMsg, 0, 0, &pInfo))
    {
	CadesFreeVerificationInfo(pInfo);
	CryptMsgClose(hMsg);
	cout << "CadesMsgVerifySignature() failed" << endl;
	return -1;
    }

    // Выводим результат проверки
    if (pInfo->dwStatus != CADES_VERIFY_SUCCESS)
	cout << "Message is not verified successfully." << endl;
    else
	cout << "Message verified successfully." << endl;

    // Освобождаем ресурсы
    if (!CadesFreeVerificationInfo(pInfo))
    {
	CryptMsgClose(hMsg);
	cout << "CadesFreeVerificationInfo() failed" << endl;
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
