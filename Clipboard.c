#include "stdio.h"
#include "windows.h"

int main()
{
    OpenClipboard(NULL);
    HANDLE h = GetClipboardData(CF_TEXT);
    printf("%s\n", (char*)h);
    CloseClipboard();
}
