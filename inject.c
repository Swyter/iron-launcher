#include <windows.h>
#include <stdio.h>

/* Global variables */
HINSTANCE dll_handle;
HINSTANCE org_handle;

char dllpath[MAX_PATH];


int __stdcall DirectInput8Create(int a1, int a2, int a3, int a4, int a5)
{
  int result; // eax@3
  FARPROC v6; // [sp+0h] [bp-114h]@2
  char LibFileName[MAX_PATH] = {0}; // [sp+4h] [bp-110h]@1
  char v8; // [sp+5h] [bp-10Fh]@1
  unsigned int v9; // [sp+10Ch] [bp-8h]@1
  HMODULE hModule; // [sp+110h] [bp-4h]@1
  int v11; // [sp+114h] [bp+0h]@1

  GetSystemDirectoryA(&LibFileName, 0x104u);
  strcat(&LibFileName, "\\dinput8.dll");
  hModule = LoadLibraryA(&LibFileName);
  if ( hModule && (v6 = GetProcAddress(hModule, "DirectInput8Create")) != 0 )
    result = ((int (__stdcall *)(int, int, int, int, int))v6)(a1, a2, a3, a4, a5);
  else
    result = -2147467259;
  return result;
}

BOOL __stdcall DllMain(
  HINSTANCE hModule,
      DWORD ulReason,
     LPVOID lpReserved
)
{
  switch(ulReason)
  {
    /* If we are attaching to a process */
    case DLL_PROCESS_ATTACH:

      /* We don't need the thread based attach/detach messages in this DLL */
      DisableThreadLibraryCalls(hModule);
      
      dll_handle = hModule;
      MessageBoxA(0, "loaded...", "lol", 0);
      break;

    /* If the process ask for unloading */
    case DLL_PROCESS_DETACH:
    
      MessageBoxA(0, "soltando la pechuga!", dllpath, 0);
      break;
  }

  // Signal for Loading/Unloading
  return (TRUE);
}