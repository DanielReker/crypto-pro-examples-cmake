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

#include "xades.h"

/*
Пример создания и проверки подписи XADES_BES с помощью упрощённых функций КриптоПро ЭЦП SDK
Пример подписывает произвольные данные, которые формирует самостоятельно. Результат
будет сохранен в файл sign.xml. Для подписи необходимо чтобы в хранилище сертификатов
присутствовал сертификат с закрытым ключом.
*/

using namespace std;

#include "../samples_util.h"

static const CHAR* XML_DATA =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"\
"<Envelope xmlns=\"urn:envelope\">"\
"<Data>"\
"Hello, World!"\
"</Data>"\
"<Node xml:id=\"nodeID\">"\
"Hello, Node!"\
"</Node>"\
"</Envelope>";

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

    // Задаем параметры
    XADES_SIGN_PARA xadesSignPara = { sizeof(xadesSignPara) };
    xadesSignPara.dwSignatureType = XML_XADES_SIGNATURE_TYPE_ENVELOPED | XADES_BES; // Указываем тип усовершенствованной обернутой (ENVELOPED) подписи XADES_BES
    xadesSignPara.pSignerCert = context;

    XADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pXadesSignPara = &xadesSignPara;

    // Формируем данные для подписания
    DWORD cbToBeSigned = (DWORD)strlen(XML_DATA);
    BYTE *pbToBeSigned = (BYTE*)XML_DATA;

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    // Создаем подписанное сообщение
    if (!XadesSign(&para, NULL, FALSE, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        cout << "XadesSign() failed" << endl;
        return -1;
    }

    vector<unsigned char> message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    // Сохраняем результат в файл sign.xml
    if (SaveVectorToFile<unsigned char>("sign.xml", message)) {
        cout << "Signed XML was not saved" << endl;
        return -1;
    }

    cout << "Signed XML was saved successfully" << endl;

    // Освобождаем структуру с закодированным подписанным сообщением
    if (!XadesFreeBlob(pSignedMessage)) {
        cout << "XadesFreeBlob() failed" << endl;
        return -1;
    }

    // Закрываем хранилище
    if (!CertCloseStore(hStoreHandle, 0)) {
        cout << "Certificate store handle was not closed." << endl;
        return -1;
    }

    // Освобождаем контекст сертифката
    if (context)
        CertFreeCertificateContext(context);

    message.clear();
    // Читаем подпись из файла
    if (ReadFileToVector("sign.xml", message))
    {
        cout << "Reading Signed XML from file \"sign.xml\" failed" << endl;
        return -1;
    }

    if (message.empty())
    {
        cout << "File \"sign.xml\" is empty. Nothing to verify." << endl;
        return -1;
    }

    // Задаем параметры проверки
    XADES_VERIFICATION_PARA xadesVerifyPara = { sizeof(xadesVerifyPara) };
    xadesVerifyPara.dwSignatureType = XADES_BES; // Указываем тип проверяемой подписи XADES_BES

    XADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };
    verifyPara.pXadesVerifyPara = &xadesVerifyPara;

    PXADES_VERIFICATION_INFO_ARRAY pVerifyInfo = 0;

    // Проверяем подпись
    if (!XadesVerify(&verifyPara, NULL, &message[0], (unsigned long)message.size(), &pVerifyInfo))
    {
        XadesFreeVerificationInfoArray(pVerifyInfo);
        cout << "XadesVerify() failed" << endl;
        return -1;
    }

    // Выводим результат проверки
    for (unsigned int i = 0; i < pVerifyInfo->cbCount; ++i) {
        if (pVerifyInfo->pXadesVerificationInfo[i].dwStatus != XADES_VERIFY_SUCCESS)
            cout << "XML signature #" << i << " is not verified successfully." << endl;
        else
            cout << "XML signature #" << i << " verified successfully." << endl;
    }

    // Освобождаем ресурсы
    if (!XadesFreeVerificationInfoArray(pVerifyInfo))
    {
        cout << "XadesFreeVerificationInfoArray() failed" << endl;
        return -1;
    }

    return 0;
}
