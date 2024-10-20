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
Пример усовершенствования подписи CADES_BES до CADES_X_LONG_TYPE_1 с помощью низкоуровневых функций КриптоПро ЭЦП SDK.
Подпись должна быть предварительно сохранена в файл sign.dat (примеры LowlevelSignCadesBes, SimplifiedSignCadesBes). 
Необходима работающая OCSP служба и ссылка на нее. sign.dat должен находится в каталоге приложения.
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

    // Открываем дескриптор сообщения для декодирования для создания усовершенствованной подписи
    HCRYPTMSG hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
    if (!hMsg) {
        cout << "CryptMsgOpenToDecode() failed" << endl;
        return -1;
    }

    // Заполняем прочитанной подписью криптографическое сообщение
    if (!CryptMsgUpdate(hMsg, &message[0], (unsigned long) message.size(), TRUE)) {
        CryptMsgClose(hMsg);
        cout << "CryptMsgUpdate() failed" << endl;
        return -1;
    }

    // Усовершенствование подписи CADES_BES до CADES_X_LONG_TYPE_1
    CADES_SERVICE_CONNECTION_PARA tspConnectionPara = {sizeof(tspConnectionPara)};
    tspConnectionPara.wszUri = SERVICE_URL_2012; // Адрес веб - сервиса со службой штампов времени

    CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
    cadesSignPara.dwCadesType = CADES_X_LONG_TYPE_1; // Указываем тип усовершенствованной подписи CADES_X_LONG_TYPE_1
    cadesSignPara.pTspConnectionPara = &tspConnectionPara;

    // Дополняем подпись, созданную в формате CADES_BES, до усовершенствованной подписи CADES_X_LONG_TYPE_1
    if (!CadesMsgEnhanceSignature(hMsg, 0, &cadesSignPara)) {
        CryptMsgClose(hMsg);
        cout << "CadesMsgEnhanceSignature() failed" << endl;
        return -1;
    }

    DWORD size = 0;
    // Получаем размер подписи
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, 0, &size)) {
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }

    message.resize(size);
    // Копируем подпись в буфер
    if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, &message[0], &size)) {
        CryptMsgClose(hMsg);
        cout << "CryptMsgGetParam() failed" << endl;
        return -1;
    }
    message.resize(size);

    // Закрываем дескриптор сообщения
    if (!CryptMsgClose(hMsg)) {
        cout << "CryptMsgClose() failed" << endl;
        return -1;
    }

    // Сохраняем подпись в файл
    if (SaveVectorToFile<unsigned char>("adv_sign.dat", message)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Signature was enhanced successfully." << endl;

    return 0;
}
