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
Пример создания подписи CADES_X_LONG_TYPE_1 с помощью низкоуровневых функций 
КриптоПро ЭЦП SDK при помощи потоков, то есть по частям. Пример подписывает 
произвольные данные, которые формирует самостоятельно. Результат будет сохранен 
в файл sign.dat. Для подписи необходимо чтобы в хранилище сертификатов присутствовал 
сертификат с закрытым ключом. Необходима работающая OCSP служба и ссылка на нее.
*/

using namespace std;

#include "../samples_util.h"

BOOL WINAPI ConvertCallback(IN const void *pvArg, IN BYTE *pbData, IN DWORD cbData, IN BOOL /*fFinal*/) {
    try {
        vector<unsigned char> *pResult = reinterpret_cast<vector<unsigned char> *>(const_cast<void *>(pvArg));
        pResult->insert(pResult->end(), pbData, pbData + cbData);
    }
    catch (...) {
        cout << "Exception in ConvertCallback" << endl;
        return 0;
    }
    return 1;
}

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

    vector<unsigned char> original;
    CMSG_STREAM_INFO stream = {};
    stream.cbContent = 0xFFFFFFFF; // неопределенная длина
    stream.pfnStreamOutput = ConvertCallback;
    stream.pvArg = &original;

    // Открываем дескриптор сообщения для создания усовершенствованной подписи
    HCRYPTMSG hMsg = CadesMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, &cadesInfo, 0, &stream);
    if (!hMsg) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CadesMsgOpenToEncode() failed" << endl;
        return -1;
    }

    // Формируем данные для подписания. Будут подписываться данные в два раза большей длины по частям.
    // Формируется первая часть, она же вторая часть.
    vector<unsigned char> data(10, 25);

    // Подписываем. Помечаем, что переданный на подпись блок данных не финальный.
    if (!CryptMsgUpdate(hMsg, &data[0], (unsigned long) data.size(), 0)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
        return -1;
    }

    // Подписываем. Помечаем, что переданный на подпись блок данных финальный.
    if (!CryptMsgUpdate(hMsg, &data[0], (unsigned long) data.size(), 1)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
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

    vector<unsigned char> message;
    stream.pvArg = &message;

    // Открываем сообщение для декодирования
    hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, &stream);
    if (!hMsg) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        cout << "CryptMsgOpenToDecode() failed" << endl;
        return -1;
    }

    // Декодируем данные по частям. Первая часть.
    if (!CryptMsgUpdate(hMsg, &original[0], 10, 0)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
        return -1;
    }

    // Декодируем данные по частям. Вторая часть, она же последняя.
    if (!CryptMsgUpdate(hMsg, &original[0] + 10, (unsigned long) original.size() - 10, 1)) {
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
    signPara.pSignerCert = 0;

    // Дополняем подпись, созданную в формате CADES_BES, до усовершенствованной подписи CADES_X_LONG_TYPE_1
    if (!CadesMsgEnhanceSignature(hMsg, 0, &signPara)) {
        CertFreeCertificateContext(context);
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CryptMsgClose(hMsg);
        cout << "CadesMsgAddEnhanceSignature() failed" << endl;
        return -1;
    }

    DWORD size = 0;
    // Получаем размер подписи.
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, 0, &size)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }

    vector<unsigned char> detached(size);
    // Копируем подпись в буффер.
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, &detached[0], &size)) {
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        CertFreeCertificateContext(context);
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }
    detached.resize(size);

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg)) {
        CertFreeCertificateContext(context);
        if (mustFree)
            CryptReleaseContext(hProv, 0);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }

    // Освобождаем ресурсы
    CertFreeCertificateContext(context);
    if (mustFree)
        CryptReleaseContext(hProv, 0);

    // Так как потоковое подписание формирует отсоединенную подпись, 
    // то далее из отсоединенной подписи необходимо сформировать присоединенную. 
    // Происходить это будет также с помощью потоков, то есть по частям.

    vector<unsigned char> convertedMessage;
    stream.pvArg = &convertedMessage;

    // Создаем контекст преобразования отсоединённой подписи в присоединённую
    PCADES_CONVERT_CONTEXT pConvert = CadesMsgConvertCreateContext(&stream, (unsigned char *) &detached[0],
                                                                   (unsigned long) detached.size());
    if (!pConvert) {
        cout << "CadesMsgCreateConvertContext() failed" << endl;
        return -1;
    }

    unsigned long chunkSize = 100;
    unsigned long chunkCount = (unsigned long) original.size() / chunkSize;
    unsigned long lastChunkSize = (unsigned long) original.size() % chunkSize;
    unsigned long lastChunkStart = chunkCount * chunkSize;

    // Передаем по частям исходное сообщение
    for (unsigned long i = 0; i < chunkCount; ++i) {
        if (!CadesMsgConvertUpdate(pConvert, &original[i * chunkSize], chunkSize, FALSE)) {
            CadesMsgConvertFreeContext(pConvert);
            cout << "CadesMsgConvertUpdate() failed" << endl;
            return -1;
        }
    }

    // Передаем последнюю часть исходного сообщения
    if (!CadesMsgConvertUpdate(pConvert, &original[lastChunkStart], lastChunkSize, 1)) {
        CadesMsgConvertFreeContext(pConvert);
        cout << "CadesMsgConvertUpdate() failed" << endl;
        return -1;
    }

    // Сохраняем подпись в файл
    if (SaveVectorToFile<unsigned char>("sign.dat", convertedMessage)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Signature was saved successfully" << endl;

    // Закрываем хранилище
    if (!CertCloseStore(hStoreHandle, 0)) {
        cout << "Certificate store handle was not closed." << endl;
        return -1;
    }

    // Освобождаем контекст преобразования
    if (!CadesMsgConvertFreeContext(pConvert)) {
        cout << "CadesMsgConvertFreeContext() failed" << endl;
        return -1;
    }

    return 0;
}
