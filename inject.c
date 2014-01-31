#include <windows.h>
#include <stdio.h>

#define E_FAIL 0x80004005

/* Global variables */
HINSTANCE self_handle;
HINSTANCE orig_handle;

char orig_path[MAX_PATH];


int __stdcall DirectInput8Create(int a1, int a2, int a3, int a4, int a5)
{
  int result; // eax@3
  FARPROC v6; // [sp+0h] [bp-114h]@2
  char v8; // [sp+5h] [bp-10Fh]@1
  unsigned int v9; // [sp+10Ch] [bp-8h]@1
  HMODULE hModule; // [sp+110h] [bp-4h]@1
  int v11; // [sp+114h] [bp+0h]@1

  GetSystemDirectoryA(&orig_path, 0x104u); strcat(&orig_path, "\\dinput8.dll");

  orig_handle = LoadLibraryA(&orig_path);
  
  
  
  if (orig_handle && (v6 = GetProcAddress(orig_handle, "DirectInput8Create")) != 0 )
    result = ((int (__stdcall *)(int, int, int, int, int))v6)(a1, a2, a3, a4, a5);
    
  else
    result = E_FAIL;
    
    
  char msg[MAX_PATH]; sprintf(msg,"hola: %x/%x/%x/%x/%p/%x/  %p/%p  %x",
                              result, a1, a2, a3, a4, a4, v6, orig_handle, self_handle);
  
  MessageBoxA(0, msg, orig_path, 0);

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
      
      self_handle = hModule;
      
      MessageBoxA(0, "loaded...", orig_path, 0);
      break;

    /* If the process ask for unloading */
    case DLL_PROCESS_DETACH:
    
      MessageBoxA(0, "unloading!", orig_path, 0);
      break;
  }

  // Signal for Loading/Unloading
  return (TRUE);
}