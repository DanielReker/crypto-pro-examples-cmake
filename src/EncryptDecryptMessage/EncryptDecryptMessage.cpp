#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <tchar.h>
#include <Windows.h>
#include <WinCrypt.h>
#include <iostream>

int main()
{
    HCRYPTPROV hProv;
    HCRYPTKEY hSesKey;
    DWORD dwFlags = 0;
    const unsigned char pbRandomData[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    if (!CryptAcquireContext(&hProv, NULL, NULL, 1, CRYPT_VERIFYCONTEXT)) // Получение хэндела криптопровайдера
    {
        std::cout << "Acquire contest error";
    }

    if (!CryptGenKey(hProv, CALG_RC4, dwFlags, &hSesKey)) // Генерация сессионого ключа
    {
        std::cout << "Gen error";
    }
    else
    {
        std::cout << "hSesKey: " << hSesKey << "\n";
    }
    char string[] = "qwertyuiofsdakjfhkjasdfhlkjasdhflkjadhiuertyieruhyfdkjsghfkdjp[]"; // Сообщение для шифрования
    DWORD count = strlen(string);

    std::cout << "Message: " << string << "\n";

    if (!CryptSetKeyParam(hSesKey, KP_IV, pbRandomData, 0))
    {
        printf("The new IV was not set.");
    }

    if (!CryptEncrypt(hSesKey, 0, true, 0, (BYTE *)string, &count, strlen(string))) // Шифрование и вывод результата
    {
        std::cout << "Error CryptEncrypt" << GetLastError() << "\n";
    }
    else
    {
        std::cout << "Encrypt: " << string << "\n";
    }

    if (!CryptSetKeyParam(hSesKey, KP_IV, pbRandomData, 0))
    {
        printf("The new IV was not set.");
    }

    if (!CryptDecrypt(hSesKey, 0, true, 0, (BYTE *)string, &count)) // Дешифрование  и вывод результата
    {
        std::cout << "Error CryptEncrypt";
    }
    else
    {
        std::cout << "Decrypt: " << string << "\n";
    }
    return 0;
}