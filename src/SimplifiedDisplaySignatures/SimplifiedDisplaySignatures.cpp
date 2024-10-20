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

using namespace std;

#include "../samples_util.h"

/*
Пример отображает в отдельном окне подписи. Подписи должны быть предварительно
сохранены в файл sign.dat (примеры LowlevelSignCades, LowlevelSignCadesBes). 
sign.dat должен находится в каталоге приложения.
*/

int main(void)
{
    vector<unsigned char> message;
    // Читаем подпись из файла
    if (ReadFileToVector("sign.dat", message))
    {
	cout << "Reading signature from file \"sign.dat\" failed" << endl;
	return -1;
    }

    if (message.empty())
    {
        cout << "File \"sign.dat\" is empty" << endl;
        return -1;
    }

    // Задаем параметры
    CADES_VIEW_SIGNATURE_PARA viewPara = { sizeof(viewPara) };
    viewPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    // Отображаем подписи в отдельном окне
    if (!CadesUIDisplaySignatures(&viewPara, &message[0], (unsigned long)message.size(), 0, L"Подпись"))
    {
	cout << "CadesUIDisplaySignatures() failed." << endl;
    }

    return 0;
}
