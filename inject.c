#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN

#include <windows.h>
#include <stdio.h>

#ifndef E_FAIL
#define E_FAIL 0x80004005
#endif
#define DI_OK 5

/* Global variables */
HINSTANCE self_handle;
HINSTANCE orig_handle;
FARPROC   orig_pointer;

char orig_path[MAX_PATH];

char *get_current_mod_name(void);


int __stdcall DirectInput8Create(int a1, int a2, int a3, int a4, int a5)
{
  int result;
  
  /* Find out where %windir%\\system32 is and append the real DLL filename */
  GetSystemDirectoryA((LPSTR)orig_path, MAX_PATH); strcat((LPSTR)orig_path, "\\dinput8.dll");

  /* Get the native function and proxy it */
  orig_handle = LoadLibraryA((LPSTR)orig_path);
  
  if (orig_handle && (orig_pointer = GetProcAddress(orig_handle, "DirectInput8Create")) != 0 )
    result = ((int (__stdcall *)(int, int, int, int, int))orig_pointer)(a1, a2, a3, a4, a5);
    
  else
    result = E_FAIL;
    
  /* Print a debug messagebox with call-related info */
  char msg[MAX_PATH]; sprintf(msg,"info: %x/%x/%x/%x/%p/%x/  %p/%p  %x  %s",
                              result, a1, a2, a3, a4, a4, orig_pointer, orig_handle, self_handle, get_current_mod_name());
  
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
      
      /* Get the module handles and paths for the parent executable and itself */
      TCHAR parent_path [MAX_PATH + 1];
      GetModuleFileName(NULL, &parent_path, MAX_PATH);
      
      HMODULE parent_handle = GetModuleHandle(NULL);
      
      self_handle = hModule;
      
      TCHAR self_path [MAX_PATH + 1];
      GetModuleFileName(self_handle, &self_path, MAX_PATH);
      
      /* Print a debug messagebox with parent-related info */
      char msg[80]; sprintf(msg,"parent exe path: %s \n"
                                "parent exe handle: %p \n"
                                "dll self handle: %p \n"
                                "dll self path: %s \n"
                                "-- \n"
                                "curr mod name: %s", parent_path, parent_handle, self_handle, self_path, get_current_mod_name() );
      MessageBoxA(0, msg, orig_path, 0);
      break;

    /* If the process ask for unloading */
    case DLL_PROCESS_DETACH:
    
      MessageBoxA(0, "unloading!", &orig_path, 0);
      break;
  }

  /* Signal for Loading/Unloading */
  return (TRUE);
}


char *get_current_mod_name(void)
{
  static char mod_name[40] = "Random stuff";
  HKEY keyThingie;
  
  // some undefined constants in TinyCC's headers
  #define KEY_WOW64_64KEY 0x0100
  #define KEY_WOW64_32KEY 0x0200
  
  RegOpenKeyEx(
    HKEY_CURRENT_USER,
   "Software\\MountAndBladeKeys",
    0,
    KEY_READ|KEY_WOW64_32KEY,
    &keyThingie
  );
    
  if(keyThingie == S_OK)
  {
    long ret = RegQueryValueEx(
        keyThingie,
       "last_module",
        0,
        0,
        mod_name,
        40
    );
    char error[80];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,0,ret,0,error,sizeof(error),0);
      
    /* Print a debug messagebox with call-related info */
    char msg[80]; sprintf(msg,"reg: %x %x %s %s", keyThingie, ret, error, mod_name);
    
    MessageBoxA(0, msg, msg, 0);
    
    RegCloseKey(keyThingie);
  }
    
  return (char*)mod_name;
}