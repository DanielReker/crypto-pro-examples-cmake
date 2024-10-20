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
Пример проверки удостоверяющей подписи, удовлетворяющей формату усовершенствованной
подписи CADES_X_LONG_TYPE_1. Предварительно удостоверяющая подпись и исходная подпись 
должны быть сохранены в файл countersign.dat (пример Countersign). countersign.dat 
должен находится в каталоге приложения. Также в хранилище сертификатов необходимо 
наличие сертификата службы штампов времени.
*/

using namespace std;

#include "../samples_util.h"

int main(void)
{
    vector<unsigned char> message;
    // Читаем подпись из файла
    if (ReadFileToVector("countersign.dat", message))
    {
	cout << "Reading signature from file \"countersign.dat\" failed" << endl;
	return -1;
    }

    if (message.empty())
    {
	cout << "File \"countersign.dat\" is empty. Nothing to verify." << endl;
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

    DWORD size = 0;
    // Получаем размер данных
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_SIGNER, 0, 0, &size))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgGetParam() failed" << endl;
	return -1;
    }

    vector<unsigned char> encodedSigner(size);
    // Получаем даные
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_SIGNER, 0, &encodedSigner[0], &size))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgGetParam() failed" << endl;
	return -1;
    }
    encodedSigner.resize(size);

    size = 0;
    // Получаем размер массива неподписанных аттрибутов подписи 
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, 0, &size))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgGetParam() failed" << endl;
	return -1;
    }
    vector<unsigned char> unsignedAttrsData(size);
    // Получаем массив неподписанных аттрибутов подписи
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, &unsignedAttrsData[0], &size))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgGetParam() failed" << endl;
	return -1;
    }
    unsignedAttrsData.resize(size);
    PCRYPT_ATTRIBUTES pAttrs = reinterpret_cast<PCRYPT_ATTRIBUTES>(&unsignedAttrsData[0]);

    // Находим в атрибутах удостоверяющую подпись
    vector<unsigned char> countersignature;
    for (unsigned long i = 0; i < pAttrs->cAttr; ++i)
    {
	if (!strcmp(szOID_RSA_counterSign, pAttrs->rgAttr[i].pszObjId))
	{
	    if (!pAttrs->rgAttr[i].cValue)
	    {
		CryptMsgClose(hMsg);
		cout << "No values in countersignature attribute." << endl;
		return -1;
	    }
	    countersignature.resize(pAttrs->rgAttr[i].rgValue[0].cbData);
	    memcpy(&countersignature[0], pAttrs->rgAttr[i].rgValue[0].pbData, countersignature.size());
	    break;
	}
    }
    if (countersignature.empty())
    {
	CryptMsgClose(hMsg);
	cout << "No countersignature found in message." << endl;
	return -1;
    }

    // Проверяем удостоверяющую подпись в соответствии с вложенными в неё доказательствами.
    // Выводим результат проверки подписи.
    if (!CadesMsgVerifyCountersignatureEncoded(0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	&encodedSigner[0], (unsigned long)encodedSigner.size(),
	&countersignature[0], (unsigned long)countersignature.size(), 0, 0, 0))
    {
	CryptMsgClose(hMsg);
	cout << "Countersignature is not verified." << endl;
	return -1;
    }
    else
	cout << "Countersignature is valid." << endl;

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg))
    {
	cout << "CryptMsgClose() failed" << endl;
	return -1;
    }
}
