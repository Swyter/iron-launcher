#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN

#include <windows.h>
#include <stdio.h>

#define E_FAIL 0x80004005
#define DI_OK 5

/* Global variables */
HINSTANCE self_handle;
HINSTANCE orig_handle;
FARPROC   orig_pointer;

char orig_path[MAX_PATH];


int __stdcall DirectInput8Create(int a1, int a2, int a3, int a4, int a5)
{
  int result;
  
  /* Find out where %windir%\\system32 is and append the real DLL filename */
  GetSystemDirectoryA(&orig_path, MAX_PATH); strcat(&orig_path, "\\dinput8.dll");

  /* Get the native function and proxy it */
  orig_handle  = LoadLibraryA(&orig_path);
  
  if (orig_handle && (orig_pointer = GetProcAddress(orig_handle, "DirectInput8Create")) != 0 )
    result = ((int (__stdcall *)(int, int, int, int, int))orig_pointer)(a1, a2, a3, a4, a5);
    
  else
    result = E_FAIL;
    
  /* Print a debug messagebox with call-related info */
  char msg[MAX_PATH]; sprintf(msg,"info: %x/%x/%x/%x/%p/%x/  %p/%p  %x",
                              result, a1, a2, a3, a4, a4, orig_pointer, orig_handle, self_handle);
  
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