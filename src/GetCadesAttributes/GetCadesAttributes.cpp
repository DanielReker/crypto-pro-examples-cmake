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
Пример получения атрибутов подписи, удовлетворяющей формату усовершенствованной 
подписи CADES_X_LONG_TYPE_1. Предварительно подпись должна быть сохранена в файл 
sign.dat (пример LowlevelSignCades). sign.dat должен находится в каталоге приложения.
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
	cout << "File \"sign.dat\" is empty" << endl;
	return -1;
    }

    // Открываем дескриптор сообщения для декодирования
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

    // Возвращаем алгоритм хэширования сертификата
    ALG_ID hashAlgId = CadesMsgGetSigningCertIdHashAlg(hMsg, 0);
    if (!hashAlgId)
    {
	CryptMsgClose(hMsg);
	cout << "CadesMsgGetSigningCertIdHashAlg() failed" << endl;
	return -1;
    }

    // Возвращаем закодированные штампы времени на подпись, вложенные в сообщение в виде массива
    PCADES_BLOB_ARRAY pTimestamps = 0;
    if (!CadesMsgGetSignatureTimestamps(hMsg, 0, &pTimestamps))
    {
	CryptMsgClose(hMsg);
	cout << "CadesGetSignatureTimestamps() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pTimestamps))
    {
	CryptMsgClose(hMsg);
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pCerts = 0;
    // Возвращаем закодированные сертификаты из доказательств подлинности подписи, вложенных в сообщение, в виде массива
    if (!CadesMsgGetCertificateValues(hMsg, 0, &pCerts))
    {
	CryptMsgClose(hMsg);
	cout << "CadesGetCertificateValues() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pCerts))
    {
	CryptMsgClose(hMsg);
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pCRLs = 0;
    PCADES_BLOB_ARRAY pOCSPs = 0;
    // Возвращаем вложенные в сообщение доказательства проверки на отзыв (закодированные списки отозванных сертификатов и закодированные ответы службы OCSP) в виде массивов
    if (!CadesMsgGetRevocationValues(hMsg, 0, &pCRLs, &pOCSPs))
    {
	CryptMsgClose(hMsg);
	cout << "CadesGetRevocationValues() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pCadesCTimestamps = 0;
    // Возвращаем закодированные штампы времени на доказательства подлинности подписи, вложенные в сообщение, в виде массива
    if (!CadesMsgGetCadesCTimestamps(hMsg, 0, &pCadesCTimestamps))
    {
	CryptMsgClose(hMsg);
	cout << "CadesMsgGetCadesCTimestamps() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pCadesCTimestamps))
    {
	CryptMsgClose(hMsg);
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pCRLs))
    {
	CryptMsgClose(hMsg);
	CadesFreeBlobArray(pOCSPs);
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pOCSPs))
    {
	CryptMsgClose(hMsg);
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg))
    {
	cout << "CryptMsgClose() failed" << endl;
	return -1;
    }

    cout << "All CAdES attributes obtained successfully." << endl;
}
