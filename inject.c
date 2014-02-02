#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN

#include <windows.h>
#include <stdio.h>

#include "inject_log_helper.h"

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

void il_configure_hooks(void)
{
  il_log(INFO, "thread started");
  
  
   // IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)GetModuleHandle( NULL ); 
   // IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)((BYTE*)pIDH + (pIDH -> e_lfanew)); 
   // IMAGE_OPTIONAL_HEADER IOH = pINH -> OptionalHeader; 
  // char coso[4000];

   // sprintf(coso, "Magic number is : %u\n", pIDH -> e_magic ); 
     // MessageBoxA(0, coso, "match", 0);

   // sprintf(coso, "Address of entry point is : %#x", IOH.AddressOfEntryPoint );  
   
  // MessageBoxA(0, coso, "match", 0);

   
  IMAGE_DOS_HEADER *dos_header = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL); //0x400000;
  IMAGE_NT_HEADERS *nt_header  = (PIMAGE_NT_HEADERS)((BYTE*)dos_header + (dos_header->e_lfanew));
  IMAGE_OPTIONAL_HEADER IOH    = nt_header -> OptionalHeader;
  
  IMAGE_IMPORT_DESCRIPTOR *imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dos_header + (nt_header-> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

  char cosa[50];
  sprintf(cosa,"image base: %x, import virtualaddr: %x first thunk: %x", nt_header-> OptionalHeader.ImageBase, nt_header-> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, imp->FirstThunk);
  MessageBoxA(0, cosa, "match", 0);

  while(1)
  {
    if (imp->OriginalFirstThunk == 0) break;
    
    sprintf(cosa,"import name: %s, first thunk: %x", (BYTE*)dos_header + imp->Name, imp->FirstThunk);
    //MessageBoxA(0, cosa, "match", 0);
    
    il_log(INFO, cosa);
    
    IMAGE_THUNK_DATA *imp_name_table = (PIMAGE_THUNK_DATA)((BYTE*)dos_header + (imp->OriginalFirstThunk));
    IMAGE_THUNK_DATA *imp_addr_table = (PIMAGE_THUNK_DATA)((BYTE*)dos_header + (imp->FirstThunk));
    
    while(1)
    {
      if (imp_name_table-> u1.AddressOfData == 0) break;
      
      char *imp_name = "Dummy";
      char ordinal[140];
      
      if (imp_name_table-> u1.ForwarderString & (1<<31))
      {
        sprintf(ordinal,"ordinal #%u", imp_name_table-> u1.ForwarderString & ~(1<<31));
        imp_name = &ordinal;
      }
      
      else
      {
        imp_name = (BYTE*)dos_header + (imp_name_table-> u1.ForwarderString + 2);
      }
        
      sprintf(cosa,"  int: %s/%x, iat: %x", imp_name, (int)imp_name_table-> u1.ForwarderString, imp_addr_table-> u1.AddressOfData);
      //MessageBoxA(0, cosa, "match", 0);
      
      il_log(INFO, cosa);

      imp_name_table++;
      imp_addr_table++;
    }
    
    
    imp++;
  }
  
  #ifndef TRUE
  char buffer[50];
  
  HMODULE handle = GetModuleHandle("SkinMagic.dll");
    
  sprintf(buffer,"SkinMagic.dll: %x",handle);

  
  MessageBoxA(0, buffer, "match", 0);

  Sleep(2*1000);

  char *p = (char *)0x400000; //0xAFB71D0;
  while(*p++ < 0xBBBBBBB)
  { // Version 1.011
    if(*p == 'V' &&
       *(p+1) == 'e' &&
       *(p+2) == 'r' &&
       *(p+3) == 's' &&
       *(p+4) == 'i' &&
       *(p+5) == 'o' &&
       *(p+6) == 'n' &&
       *(p+7) == ' ' &&
       *(p+8) == '1' &&
       *(p+8) == '.')
    {
      il_log(WARN, "LOL TRONQUI");
      //il_log(INFO, p);
      
      strncpy(buffer, p, sizeof(buffer));
      
      MessageBoxA(0, buffer, "match", 0);

      //strcpy(p, "hola cara de bola");
      
      break;
    }
  }
  #endif
  // while(1)
  // {
    // Sleep(2*1000);
    // il_log(INFO, "heartbeat! <3");
  // }
  
  return 1;

}


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
      char msg[MAX_PATH]; sprintf(msg,"parent exe path: %s \n"
                                      "parent exe handle: %p \n"
                                      "dll self handle: %p \n"
                                      "dll self path: %s \n"
                                      "-- \n"
                                      "curr mod name: %s", parent_path, parent_handle, self_handle, self_path, get_current_mod_name() );
      MessageBoxA(0, msg, orig_path, 0);
      il_log(INFO, msg);
      
      /* Do the rest of the stuff in a new thread to avoid blocking the entire program */
      HANDLE threat_id = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)&il_configure_hooks,
        NULL,
        NULL,
        0//'IL'
      );
      
      SetThreadPriority(threat_id, THREAD_PRIORITY_TIME_CRITICAL);
      
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
  static char mod_name[MAX_PATH] = "Random stuff";
  HKEY key_thingie;
  
  // some undefined constants in TinyCC's headers
  #define KEY_WOW64_64KEY 0x0100
  #define KEY_WOW64_32KEY 0x0200
  
  HRESULT lResult = RegOpenKeyEx(
    HKEY_CURRENT_USER,
   "Software\\MountAndBladeKeys",
    0,
    KEY_READ|KEY_WOW64_32KEY,
    &key_thingie
  );
    
  if(lResult == ERROR_SUCCESS)
  {
  
    DWORD ktype = REG_SZ, ksize = sizeof(mod_name);
  
    RegQueryValueEx(
        key_thingie,
       "last_module",
        NULL,
       &ktype,
       &mod_name,
       &ksize
    );
    
    RegCloseKey(key_thingie);
   }
    
  return (char*)mod_name;
}