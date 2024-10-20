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

/*
Пример проверки подписи CADES_BES с помощью упрощённых функций КриптоПро ЭЦП SDK.
Пример проверяет присоединенную подпись. Результат проверки будет выведен на консоль.
Подпись должна быть предварительно сохранена в файл sign.dat (пример SimplifiedSignCades). 
sign.dat должен находится в каталоге приложения.
*/

using namespace std;

#include "../samples_util.h"

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
	cout << "File \"sign.dat\" is empty. Nothing to verify." << endl;
	return -1;
    }
    
    // Задаем параметры проверки
    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
    cadesVerifyPara.dwCadesType = CADES_BES; // Указываем тип проверяемой подписи CADES_BES

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };
    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo = 0;
    PCRYPT_DATA_BLOB pContent = 0;

    // Проверяем подпись
    if (!CadesVerifyMessage(&verifyPara, 0, &message[0], (unsigned long)message.size(), &pContent, &pVerifyInfo))
    {
	CadesFreeVerificationInfo(pVerifyInfo);
	cout << "CadesVerifyMessage() failed" << endl;
	return -1;
    }

    // Выводим результат проверки
    if (pVerifyInfo->dwStatus != CADES_VERIFY_SUCCESS)
	cout << "Message is not verified successfully." << endl;
    else
	cout << "Message verified successfully." << endl;

    // Освобождаем ресурсы
    if (!CadesFreeVerificationInfo(pVerifyInfo))
    {
	CadesFreeBlob(pContent);
	cout << "CadesFreeVerificationInfo() failed" << endl;
	return -1;
    }

    if (!CadesFreeBlob(pContent))
    {
	cout << "CadesFreeBlob() failed" << endl;
	return -1;
    }

    return 0;
}
