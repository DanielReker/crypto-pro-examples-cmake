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
Пример получения атрибутов удостоверяющей подписи, удовлетворяющей формату усовершенствованной
подписи CADES_X_LONG_TYPE_1. Предварительно удостоверяющая подпись и исходная подпись должны быть
сохранены в файл countersign.dat (пример Countersign). countersign.dat должен находится в каталоге приложения.
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
	cout << "File \"countersign.dat\" is empty" << endl;
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

    // Получаем неподписанные атрибуты. Одним из неподписанных атрибутов
    // является удостоверяющая подпись.
    DWORD size = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, 0, &size))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgGetParam() failed" << endl;
	return -1;
    }
    vector<unsigned char> paramBlob(size);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, &paramBlob[0], &size))
    {
	CryptMsgClose(hMsg);
	cout << "CryptMsgGetParam() failed" << endl;
	return -1;
    }
    paramBlob.resize(size);
    PCRYPT_ATTRIBUTES pAttrs = reinterpret_cast<PCRYPT_ATTRIBUTES>(&paramBlob[0]);

    // Сообщение больше не понадобится.
    if (!CryptMsgClose(hMsg))
    {
	cout << "CryptMsgClose() failed" << endl;
	return -1;
    }

    // Поиск атрибута в котором хранится удостоверяющая подпись. В этом
    // примере берётся первая найденная подпись, но в дейтсвительности их
    // может быть несколько.
    CRYPT_DATA_BLOB countersignatureBlob = { 0, 0 };
    for (unsigned long i = 0; i < pAttrs->cAttr; ++i)
    {
	PCRYPT_ATTRIBUTE pAttr = &pAttrs->rgAttr[i];
	if (!strcmp(szOID_RSA_counterSign, pAttr->pszObjId))
	{
	    if (!pAttr->cValue)
		continue;
	    countersignatureBlob.pbData = pAttr->rgValue[0].pbData;
	    countersignatureBlob.cbData = pAttr->rgValue[0].cbData;
	    break;
	}
    }

    if (!countersignatureBlob.cbData)
    {
	cout << "Countersignature not found" << endl;
	return -1;
    }

    // Атрибут удостоверяющей подписи имеет формат CMSG_SIGNER_INFO,
    // и его можно раскодировать с помощью CryptDecodeObject().
    size = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO, countersignatureBlob.pbData, countersignatureBlob.cbData, 0, 0, &size))
    {
	cout << "CryptDecodeObject() failed" << endl;
	return -1;
    }

    vector<unsigned char> decodeBlob(size);
    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO, countersignatureBlob.pbData, countersignatureBlob.cbData, 0, &decodeBlob[0], &size))
    {
	cout << "CryptDecodeObject() failed" << endl;
	return -1;
    }

    PCMSG_SIGNER_INFO pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(&decodeBlob[0]);

    // Получаем алгоритм хэширования сертификата
    ALG_ID hashAlgId = CadesMsgGetSigningCertIdHashAlgEx(pSignerInfo);
    if (!hashAlgId)
    {
	cout << "CadesMsgGetSigningCertIdHashAlg() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pTimestamps = 0;
    // Получаем штампы времени на подпись, вложенные в подпись.
    if (!CadesMsgGetSignatureTimestampsEx(pSignerInfo, &pTimestamps))
    {
	cout << "CadesGetSignatureTimestamps() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pTimestamps))
    {
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pCerts = 0;
    // Получаем сертификаты из доказательств подлинности, вложенных в подпись
    if (!CadesMsgGetCertificateValuesEx(pSignerInfo, &pCerts))
    {
	cout << "CadesGetCertificateValues() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pCerts))
    {
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pCRLs = 0;
    PCADES_BLOB_ARRAY pOCSPs = 0;
    // Возвращаем вложенные в подпись доказательства проверки на отзыв (закодированные списки отозванных сертификатов и закодированные ответы службы OCSP) в виде массивов.
    if (!CadesMsgGetRevocationValuesEx(pSignerInfo, &pCRLs, &pOCSPs))
    {
	cout << "CadesGetRevocationValues() failed" << endl;
	return -1;
    }

    PCADES_BLOB_ARRAY pCadesCTimestamps = 0;
    // Возвращаем закодированные штампы времени на вложенные в подпись доказательства подлинности в виде массива
    if (!CadesMsgGetCadesCTimestampsEx(pSignerInfo, &pCadesCTimestamps))
    {
	cout << "CadesMsgGetCadesCTimestamps() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pCadesCTimestamps))
    {
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pCRLs))
    {
	CadesFreeBlobArray(pOCSPs);
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlobArray(pOCSPs))
    {
	cout << "CadesFreeBlobArray() failed" << endl;
	return -1;
    }

    cout << "All CAdES countersignature attributes obtained successfully." << endl;

}
