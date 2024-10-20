#pragma warning(disable : 4996)

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
Пример создания усовершенствованной подписи CADES_X_LONG_TYPE_1 с помощью
упрощённых функций КриптоПро ЭЦП SDK по хэш-значению. Пример подписывает
произвольные данные, которые формирует самостоятельно. Результат будет сохранен
в файл sign.dat. Для подписи необходимо чтобы в хранилище сертификатов
присутствовал сертификат с закрытым ключом и ссылкой на работающую OCSP службу
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
        CertCloseStore(hStoreHandle, 0);
        cout << "There is no certificate with a CERT_KEY_CONTEXT_PROP_ID "
             << endl << "property and an AT_KEYEXCHANGE private key available."
             << endl
             << "While the message could be sign, in this case, it could"
             << endl << "not be verify in this program." << endl
             << "For more information, read the documentation "
                "http://cpdn.cryptopro.ru/" << endl;
        return -1;
    }

    HCRYPTPROV hProv(0);

    DWORD dwProvType = PROV_GOST_2001_DH;

    // Получаем ссылку на закрытый ключ сертификата и дестриптор
    // криптопровайдера
    if (!CryptAcquireContext(&hProv, 0, NULL, dwProvType,
                             CRYPT_VERIFYCONTEXT)) {
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CryptAcquireContext() failed" << endl;
        return -1;
    }

    // Задаем параметры
    CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = context;
    signPara.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(context);

    CADES_SERVICE_CONNECTION_PARA tspConnectionPara = {
            sizeof(tspConnectionPara)};
    tspConnectionPara.wszUri = SERVICE_URL_2012; // Адрес веб - сервиса со службой штампов времени

    CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
    cadesSignPara.dwCadesType =
            CADES_X_LONG_TYPE_1; // Указываем тип усовершенствованной подписи
    // CADES_X_LONG_TYPE_1
    cadesSignPara.pTspConnectionPara = &tspConnectionPara;

    CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    // Формируем данные для подписания
    vector<unsigned char> data(10, 25);

    // Получение хэша данных
    HCRYPTHASH hash(0);
    if (!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hash)) {
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CryptCreateHash() failed" << endl;
        return -1;
    }

    DWORD cbToBeSigned(0);
    DWORD cb = sizeof(cbToBeSigned);
    BYTE *pbToBeSigned;

    if (!CryptHashData(hash, &data[0], (DWORD)data.size(), 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CryptHashData() failed" << endl;
        return -1;
    }

    if (!CryptGetHashParam(hash, HP_HASHSIZE, (LPBYTE)&cbToBeSigned, &cb, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CryptGetHashParam() failed" << endl;
        return -1;
    }

    pbToBeSigned = new BYTE[cbToBeSigned];
    if (!CryptGetHashParam(hash, HP_HASHVAL, pbToBeSigned, &cbToBeSigned, 0)) {
        delete[] pbToBeSigned;
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CryptGetHashParam() failed" << endl;
        return -1;
    }

    PCRYPT_DATA_BLOB pSignedMessage = 0;

    string contentType(szOID_RSA_data);

    // Создаем подписанное сообщение
    if (!CadesSignHash(&para, pbToBeSigned, cbToBeSigned, contentType.c_str(),
                       &pSignedMessage)) {
        delete[] pbToBeSigned;
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CadesSignHash() failed" << endl;
        return -1;
    }

    delete[] pbToBeSigned;

    vector<unsigned char> message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData,
         pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    // Сохраняем результат в файл sign.dat
    if (SaveVectorToFile<unsigned char>("sign.dat", message)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CryptHashData() failed" << endl;
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Signature was saved successfully" << endl;

    // Освобождаем структуру с закодированным подписанным сообщением
    if (!CadesFreeBlob(pSignedMessage)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        cout << "CadesFreeBlob() failed" << endl;
        return -1;
    }

    // Закрываем хранилище
    if (!CertCloseStore(hStoreHandle, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "Certificate store handle was not closed." << endl;
        return -1;
    }

    // Освобождаем ресурсы
    CryptDestroyHash(hash);
    CryptReleaseContext(hProv, 0);
    CertFreeCertificateContext(context);

    return 0;
}
