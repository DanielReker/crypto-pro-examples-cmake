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
Пример проверки подписи CADES_BES с помощью низкоуровневых функций КриптоПро ЭЦП SDK.
Пример проверяет присоединенную подпись. Результат проверки будет выведен на консоль.
Подпись должна быть предварительно сохранена в файл sign.dat (пример LowlevelSignCadesBes).
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
 
    // Открываем дескриптор сообщения для декодирования для проверки усовершенствованной подписи
    HCRYPTMSG hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
    if (!hMsg)
    {
	cout << "CryptMsgOpenToDecode() failed" << endl;
	return -1;
    }

    // Заполняем прочитанной подписью криптографическое сообщение
    if (!CryptMsgUpdate(hMsg, &message[0], (unsigned long) message.size(), 1))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgUpdate() failed" << endl;
	return -1;
    }

    // Проверка на соответствие типу CADES_BES при помощи функции CadesMsgIsType.
    // Данная проверка приведена здесь в качестве примера использования
    // функции CadesMsgIsType и не является обязательной при проверке подписи.
    int bResult = false;

    if (!CadesMsgIsType(hMsg, 0, CADES_BES, &bResult))
    {
	CryptMsgClose(hMsg);
	cout << "CadesMsgIsType() failed" << endl;
	return -1;
    }

    if (!bResult)
    {
	CryptMsgClose(hMsg);
	cout << "Message is not CAdES-BES message." << endl;
	return -1;
    }

    cout << "Message is CAdES-BES message." << endl;

    // Проверка подписи CADES_BES
    PCADES_VERIFICATION_INFO pInfo = 0;

    CADES_VERIFICATION_PARA verificationPara = { sizeof(verificationPara) };
    verificationPara.dwCadesType = CADES_BES; // Указываем тип усовершенствованной подписи CADES_BES

    // Проверяем подпись сообщения
    if (!CadesMsgVerifySignature(hMsg, 0, &verificationPara, &pInfo))
    {
	CadesFreeVerificationInfo(pInfo);
	CryptMsgClose(hMsg);
	cout << "CadesMsgVerifySignature() failed" << endl;
	return -1;
    }

    // Выводим результат проверки
    if (pInfo->dwStatus != CADES_VERIFY_SUCCESS)
	cout << "CAdES-BES message is not verified successfully." << endl;
    else
	cout << "CAdES-BES message verified successfully." << endl;

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
