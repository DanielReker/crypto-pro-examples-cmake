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
Пример создания отсоединенной подписи CADES_X_LONG_TYPE_1 с помощью низкоуровневых функций 
КриптоПро ЭЦП SDK. Пример подписывает произвольные данные, которые формирует самостоятельно.
Результат будет сохранен в файл sign.dat. Для подписи необходимо чтобы в хранилище сертификатов 
присутствовал сертификат с закрытым ключом. Необходима работающая OCSP служба и ссылка на нее.
*/

using namespace std;

#include "../samples_util.h"

int main(int argc, char *argv[]) {
    // Открываем хранилище сертификатов пользователя
    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));
    if (!hStoreHandle) {
        cout << "Store handle was not got" << endl;
        return -1;
    }

    wchar_t *wa = NULL;
    if (argc > 1) {
        size_t len = strlen(argv[1]) + 1;
        wa = new wchar_t[len];
        mbstowcs(wa, argv[1], len);
    }

    // Получаем сертификат для подписания
    PCCERT_CONTEXT context = GetRecipientCert(hStoreHandle, wa);
    if (wa) delete[] wa;

    // Если сертификат не найден, завершаем работу
    if (!context) {
        cout << "There is no certificate with a CERT_KEY_CONTEXT_PROP_ID " << endl
             << "property and an AT_KEYEXCHANGE private key available." << endl
             << "While the message could be sign, in this case, it could" << endl
             << "not be verify in this program." << endl
             << "For more information, read the documentation http://cpdn.cryptopro.ru/" << endl;
        return -1;
    }

    int mustFree;
    DWORD dwKeySpec = 0;
    HCRYPTPROV hProv;

    // Получаем ссылку на закрытый ключ сертификата и дестриптор криптопровайдера
    if (!CryptAcquireCertificatePrivateKey(context, 0, 0, &hProv, &dwKeySpec, &mustFree)) {
        cout << "CryptAcquireCertificatePrivateKey() failed" << "GetLastError() = " << GetLastError() << endl;
        CertFreeCertificateContext(context);
        return -1;
    }

    // Задаем параметры
    CMSG_SIGNER_ENCODE_INFO signer = {sizeof(CMSG_SIGNER_ENCODE_INFO)};
    signer.pCertInfo = context->pCertInfo; // Сертификат подписчика
    signer.hCryptProv = hProv; // Дескриптор криптопровайдера
    signer.dwKeySpec = dwKeySpec;
    signer.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(context);

    CMSG_SIGNED_ENCODE_INFO info = {sizeof(CMSG_SIGNED_ENCODE_INFO)};
    info.cSigners = 1; // Количество подписчиков
    info.rgSigners = &signer; // Массив подписчиков

    CADES_ENCODE_INFO cadesInfo = {sizeof(cadesInfo)};
    cadesInfo.pSignedEncodeInfo = &info;

    // Открываем дескриптор сообщения для создания усовершенствованной подписи
    HCRYPTMSG hMsg = CadesMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, &cadesInfo, 0,
                                          0);

    if (!hMsg) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CadesMsgOpenToEncode() failed" << endl;
        return -1;
    }

    // Формируем данные для подписания
    vector<unsigned char> data(10, 25);

    // Формируем подпись в сообщении
    if (!CryptMsgUpdate(hMsg, &data[0], (unsigned long) data.size(), 1)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
        return -1;
    }

    DWORD size = 0;
    // Получаем размер подписи
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, 0, &size)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }

    vector<unsigned char> message(size);
    // Получаем подпись
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, &message[0], &size)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }
    message.resize(size);

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }

    // Снова открываем дескриптор сообщения для декодирования для создания усовершенствованной подписи
    hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0, 0, 0);
    if (!hMsg) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CryptMsgOpenToDecode() failed" << endl;
        return -1;
    }

    // Добавляем подпись в сообщение
    if (!CryptMsgUpdate(hMsg, &message[0], (unsigned long) message.size(), TRUE)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
        return -1;
    }

    // Задаем параметры
    CADES_SERVICE_CONNECTION_PARA tspConnectionPara = {sizeof(tspConnectionPara)};
    tspConnectionPara.wszUri = SERVICE_URL_2012; // Адрес веб - сервиса со службой штампов времени

    CADES_SIGN_PARA signPara = {sizeof(signPara)};
    signPara.dwCadesType = CADES_X_LONG_TYPE_1; // Указываем тип усовершенствованной подписи CADES_X_LONG_TYPE_1
    signPara.pTspConnectionPara = &tspConnectionPara;

    // Дополняем подпись, созданную в формате CADES_BES, до усовершенствованной подписи CADES_X_LONG_TYPE_1
    if (!CadesMsgEnhanceSignature(hMsg, 0, &signPara)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CadesMsgEnhanceSignature() failed" << endl;
        return -1;
    }

    size = 0;
    // Получаем размер подписи
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, 0, &size)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }

    message.resize(size);
    // Копируем подпись в буфер
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, &message[0], &size)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }
    message.resize(size);

    // Закрываем хранилище
    if (!CertCloseStore(hStoreHandle, 0)) {
        cout << "Certificate store handle was not closed." << endl;
        return -1;
    }

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CryptMsgClose() failed" << endl;
        return -1;
    }

    // Освобождаем ресурсы
    if (mustFree)
        CryptReleaseContext(hProv, 0);
    CertFreeCertificateContext(context);

    // Сохраняем результат в файл sign.dat
    if (SaveVectorToFile<unsigned char>("sign.dat", message)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Signature was saved successfully" << endl;

    return 0;
}
