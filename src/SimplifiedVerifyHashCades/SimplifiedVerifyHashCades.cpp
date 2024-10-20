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
Пример проверки подписи CADES_X_LONG_TYPE_1 с помощью упрощённых функций
КриптоПро ЭЦП SDK по хэш-значению. Пример проверяет отсоединенную подпись.
Результат проверки будет выведен на консоль. Подпись должна быть предварительно
сохранена в файл sign.dat (пример SimplifiedSignHashCades). sign.dat должен
находится в каталоге приложения. Также в хранилище сертификатов необходимо
наличие сертификата службы штампов времени.
*/

using namespace std;

#include "../samples_util.h"

int main(void) {
    vector<unsigned char> message;
    // Читаем подпись из файла
    if (ReadFileToVector("sign.dat", message)) {
        cout << "Reading signature from file \"sign.dat\" failed" << endl;
        return -1;
    }

    if (message.empty()) {
        cout << "File \"sign.dat\" is empty. Nothing to verify." << endl;
        return -1;
    }

    // Задаем параметры проверки
    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = {sizeof(cryptVerifyPara)};
    cryptVerifyPara.dwMsgAndCertEncodingType =
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cadesVerifyPara = {sizeof(cadesVerifyPara)};
    cadesVerifyPara.dwCadesType = CADES_X_LONG_TYPE_1; // Указываем тип
    // проверяемой подписи
    // CADES_X_LONG_TYPE_1

    CADES_VERIFY_MESSAGE_PARA verifyPara = {sizeof(verifyPara)};
    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo = 0;

    // Формируем данные для проверки подписи
    vector<unsigned char> data(10, 25);

    HCRYPTPROV hProv(0);
    DWORD dwProvType = PROV_GOST_2001_DH;

    // Получение дескриптора криптографического провайдера.
    if (!CryptAcquireContext(&hProv, 0, NULL, dwProvType,
                             CRYPT_VERIFYCONTEXT)) {
        cout << "CryptAcquireContext() failed" << endl;
        return -1;
    }

    // Получение хэша данных
    HCRYPTHASH hash(0);
    if (!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hash)) {
        CryptReleaseContext(hProv, 0);
        cout << "CryptCreateHash() failed" << endl;
        return -1;
    }

    if (!CryptHashData(hash, &data[0], (DWORD)data.size(), 0)){
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        cout << "CryptHashData() failed" << endl;
        return -1;
    }

    DWORD cbHash(0);
    DWORD cb = sizeof(cbHash);
    BYTE *pbHash;

    if (!CryptGetHashParam(hash, HP_HASHSIZE, (LPBYTE)&cbHash, &cb, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        cout << "CryptGetHashParam() failed" << endl;
        return -1;
    }

    pbHash = new BYTE[cbHash];

    if (!CryptGetHashParam(hash, HP_HASHVAL, pbHash, &cbHash, 0)) {
        delete[] pbHash;
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        cout << "CryptGetHashParam() failed" << endl;
        return -1;
    }

    CRYPT_ALGORITHM_IDENTIFIER alg;
    memset(&alg, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    size_t length = strlen(szOID_CP_GOST_R3411_12_256);
    vector<CHAR> szObjId(length + 1);
    alg.pszObjId = &szObjId[0];
    memcpy(alg.pszObjId, szOID_CP_GOST_R3411_12_256, length + 1);

    // Проверяем подпись
    if (!CadesVerifyHash(&verifyPara, 0, &message[0],
                         (unsigned long)message.size(), pbHash, cbHash, &alg,
                         &pVerifyInfo)) {
        delete[] pbHash;
        CadesFreeVerificationInfo(pVerifyInfo);
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        cout << "CadesVerifyHash() failed" << endl;
        return -1;
    }

    // Выводим результат проверки
    if (pVerifyInfo->dwStatus != CADES_VERIFY_SUCCESS)
        cout << "Message is not verified successfully." << endl;
    else
        cout << "Message verified successfully." << endl;

    // Освобождаем ресурсы
    if (!CadesFreeVerificationInfo(pVerifyInfo)) {
        delete[] pbHash;
        CryptDestroyHash(hash);
        CryptReleaseContext(hProv, 0);
        cout << "CadesFreeVerificationInfo() failed" << endl;
        return -1;
    }

    delete[] pbHash;
    CryptDestroyHash(hash);
    CryptReleaseContext(hProv, 0);

    return 0;
}
