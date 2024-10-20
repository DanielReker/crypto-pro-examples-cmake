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
Пример показывает в отдельном окне список отсоединенных усовершенствованных подписей. Предварительно подписи должны быть
созданы и сохранены в файл sign.dat (пример LowlevelSignDetachedCades). sign.dat должен находится в каталоге приложения.
*/

using namespace std;

#include "../samples_util.h"

int main(void)
{
    // Формируем такие же данные данные для подписи как и при формировании (пример LowlevelSignDetachedCades).
    vector<unsigned char> original(10, 25);

    vector<unsigned char> detachedMsg;
    // Читаем из файла отсоединенные подписи
    if (ReadFileToVector("sign.dat", detachedMsg))
    {
	cout << "Reading signature from file \"sign.dat\" failed" << endl;
	return -1;
    }

    if (detachedMsg.empty())
    {
        cout << "File \"sign.dat\" is empty" << endl;
        return -1;
    }

    const unsigned char* pDataArray[1];
    pDataArray[0] = &original[0];

    unsigned long cDataArray[1];
    cDataArray[0] = (unsigned long)original.size();

    CADES_VIEW_SIGNATURE_PARA viewPara = { sizeof(viewPara) };
    viewPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    LPCPROPSHEETPAGEW *pPropSheetPages = 0;
    unsigned long cPropSheetPages = 0;

    // Возвращаем массив указателей на структуры PROPSHEETPAGE, содержащие по одному элементу, соответствующему странице со списком отделенных УЭЦП
    if (!CadesViewSignatureDetached(&viewPara, 0, &detachedMsg[0], (unsigned long)detachedMsg.size(), 1, pDataArray, cDataArray, &pPropSheetPages, &cPropSheetPages))
    {
        CadesFreeSignaturePropPages(pPropSheetPages, cPropSheetPages);
        cout << "CadesViewSignatureDetached() failed." << endl;
        return -1;
    }

    // Создаем страницы
    vector<HPROPSHEETPAGE> pages(cPropSheetPages);
    for (unsigned long i = 0; i < cPropSheetPages; i++)
    {
	pages[i] = ::CreatePropertySheetPage(pPropSheetPages[i]);
    }

    // Задаем параметры
    PROPSHEETHEADER psh = {};
    psh.pszCaption = L"Подпись";
    psh.dwSize = sizeof(PROPSHEETHEADER);
    psh.hwndParent = 0;
    psh.nPages = cPropSheetPages;
    psh.phpage = &pages[0];
    psh.dwFlags = PSH_NOAPPLYNOW | PSH_NOCONTEXTHELP | PSH_USECALLBACK;

    INT_PTR ret;
    // Показываем первую подпись
    ret = ::PropertySheet(&psh);
    if (ret < 0)
    {
	cout << "View Detached Signature failed." << endl;
    }

    // Освобождаем массив указателей
    CadesFreeSignaturePropPages(pPropSheetPages, cPropSheetPages);
}
