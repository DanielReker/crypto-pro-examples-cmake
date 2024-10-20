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
Пример усовершенствования подписи CADES_BES до CADES_X_LONG_TYPE_1 с помощью
упрощённых функций КриптоПро ЭЦП SDK. Подпись должна быть предварительно сохранена 
в файл sign.dat (примеры SimplifiedSignCadesBes, LowlevelSignCadesBes). sign.dat
должен находится в каталоге приложения. Результат будет сохранен в файл adv_sign.dat. 
Необходима работающая OCSP служба и ссылка на нее.
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
        cout << "File \"sign.dat\" is empty. Nothing to enhance" << endl;
        return -1;
    }

    // Задаем параметры
    CADES_SERVICE_CONNECTION_PARA tspConnectionPara = {sizeof(tspConnectionPara)};
    tspConnectionPara.wszUri = SERVICE_URL_2012; // Адрес веб - сервиса со службой штампов времени

    CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
    cadesSignPara.dwCadesType = CADES_X_LONG_TYPE_1; // Указываем тип усовершенствованной подписи CADES_X_LONG_TYPE_1
    cadesSignPara.pTspConnectionPara = &tspConnectionPara;

    CADES_ENHANCE_MESSAGE_PARA para = {sizeof(para)};
    para.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    para.pCadesSignPara = &cadesSignPara;

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    // Дополняем подпись, созданную в формате CADES_BES, до усовершенствованной подписи CADES_X_LONG_TYPE_1
    if (!CadesEnhanceMessage(&para, 0, &message[0], (unsigned long) message.size(), &pSignedMessage)) {
        cout << "CadesEnhanceMessage() failed" << endl;
        return -1;
    }

    message.resize(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    // Сохраняем подпись CADES_X_LONG_TYPE_1 в файл adv_sign.dat
    if (SaveVectorToFile<unsigned char>("adv_sign.dat", message)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    // Освобождаем ресурсы
    if (!CadesFreeBlob(pSignedMessage)) {
        cout << "CadesFreeBlob() failed" << endl;
        return -1;
    }

    cout << "Signature was enhanced and saved successfully." << endl;

    return 0;
}
