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
Пример добавления усовершенствованной подписи формата CADES_X_LONG_TYPE_1 к уже существующей 
усовершенствованной подписи. Для работы примера первоначальная подпись должна быть сохранена
в файл sign.dat (LowlevelSignCades, LowlevelSignCadesBes). sign.dat должен находится в каталоге 
приложения. Для подписи необходимо чтобы в хранилище сертификатов присутствовал сертификат с
закрытым ключом. Необходима работающая OCSP служба и ссылка на нее.
*/

using namespace std;

#include "../samples_util.h"

int main(int argc, char *argv[]) {
    vector<unsigned char> message;

    // Читаем подпись из файла
    if (ReadFileToVector("sign.dat", message)) {
        cout << "Reading signature from file \"sign.dat\" failed" << endl;
        return -1;
    }

    if (message.empty()) {
        cout << "File \"sign.dat\" is empty" << endl;
        return -1;
    }

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

    // Открываем дескриптор сообщения для создания усовершенствованной подписи
    HCRYPTMSG hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
    if (!hMsg) {
        CertFreeCertificateContext(context);
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        cout << "CryptMsgOpenToDecode() failed" << endl;
        return -1;
    }

    // Заполняем прочитанной подписью криптографическое сообщение
    if (!CryptMsgUpdate(hMsg, &message[0], (unsigned long) message.size(), 1)) {
        CertFreeCertificateContext(context);
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
        return -1;
    }

    // Задаем параметры
    CMSG_SIGNER_ENCODE_INFO signer = {sizeof(CMSG_SIGNER_ENCODE_INFO)};
    signer.pCertInfo = context->pCertInfo; // Сертификат подписчика
    signer.hCryptProv = hProv; // Дескриптор криптопровайдера
    signer.dwKeySpec = dwKeySpec;
    signer.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(context);

    CADES_SERVICE_CONNECTION_PARA tspConnectionPara = {sizeof(tspConnectionPara)};
    tspConnectionPara.wszUri = SERVICE_URL_2012; // Адрес веб - сервиса со службой штампов времени

    CADES_SIGN_PARA signPara = {sizeof(signPara)};
    signPara.dwCadesType = CADES_X_LONG_TYPE_1; // Указываем тип усовершенствованной подписи CADES_X_LONG_TYPE_1
    signPara.pTspConnectionPara = &tspConnectionPara;

    CADES_COSIGN_PARA cosignPara = {sizeof(cosignPara)};
    cosignPara.pSigner = &signer;
    cosignPara.pCadesSignPara = &signPara;

    // Добавляем новую усовершенствованную подпись в сообщение
    if (!CadesMsgAddEnhancedSignature(hMsg, &cosignPara)) {
        CertFreeCertificateContext(context);
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CryptMsgClose(hMsg);
        cout << "CadesMsgAddEnhanceSignature() failed" << endl;
        return -1;
    }

    DWORD size = 0;
    // Получаем размер подписи в сообщении
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
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CryptMsgClose() failed" << endl;
        return -1;
    }

    // Освобождаем ресурсы
    if (mustFree)
        CryptReleaseContext(hProv, 0);
    CertFreeCertificateContext(context);

    // Сохраняем результат в файл sign_add.dat
    if (SaveVectorToFile<unsigned char>("sign_add.dat", message)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Enhanced signature was added successfully" << endl;

    return 0;
}
