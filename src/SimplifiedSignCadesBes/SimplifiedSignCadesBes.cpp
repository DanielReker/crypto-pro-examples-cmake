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
Пример создания подписи CADES_BES с помощью упрощённых функций КриптоПро ЭЦП SDK
Пример подписывает произвольные данные, которые формирует самостоятельно. Результат
будет сохранен в файл sign.dat. Для подписи необходимо чтобы в хранилище сертификатов
присутствовал сертификат с закрытым ключом.
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

    // Задаем параметры 
    CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = context;
    signPara.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(context);

    CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
    cadesSignPara.dwCadesType = CADES_BES; // Указываем тип усовершенствованной подписи CADES_BES

    CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    // Формируем данные для подписания
    vector<unsigned char> data(10, 25);
    const unsigned char *pbToBeSigned[] = {&data[0]};
    DWORD cbToBeSigned[] = {(DWORD) data.size()};


    CERT_CHAIN_PARA		ChainPara = { sizeof(ChainPara) };
    PCCERT_CHAIN_CONTEXT	pChainContext = NULL;

    std::vector<PCCERT_CONTEXT> certs;

    if (CertGetCertificateChain(
	NULL,
	context,
	NULL,
	NULL,
	&ChainPara,
	0,
	NULL,
	&pChainContext)) {

	for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement-1; ++i)
	{
	    certs.push_back(pChainContext->rgpChain[0]->rgpElement[i]->pCertContext);
	}
    }
    // Добавляем в сообщение цепочку сертификатов без корневого
    if (certs.size() > 0)
    {
	signPara.cMsgCert = (DWORD)certs.size();
	signPara.rgpMsgCert = &certs[0];
    }


    PCRYPT_DATA_BLOB pSignedMessage = 0;
    // Создаем подписанное сообщение
    if (!CadesSignMessage(&para, 0, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        cout << "CadesSignMessage() failed" << endl;
        return -1;
    }
    if (pChainContext)
	CertFreeCertificateChain(pChainContext);

    vector<unsigned char> message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    // Сохраняем результат в файл sign.dat
    if (SaveVectorToFile<unsigned char>("sign.dat", message)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Signature was saved successfully" << endl;

    // Освобождаем структуру с закодированным подписанным сообщением
    if (!CadesFreeBlob(pSignedMessage)) {
        cout << "CadesFreeBlob() failed" << endl;
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

    return 0;
}
