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

BOOL FileExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
        !(dwAttrib  & FILE_ATTRIBUTE_DIRECTORY));
}


HANDLE __stdcall il_CreateFile(
  LPCTSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
   HANDLE hTemplateFile
)
{

  char debug[500]; sprintf(debug,"CreateFile called! (lpFileName=%s,dwDesiredAccess=%x,dwShareMode=%x)",
                           lpFileName, dwDesiredAccess, dwShareMode);
  il_log(INFO,debug);
  
  static struct{const char *src; const char *dst;} search_locations[] =
  {
    { "Data\\font_data.xml",           "Modules\\%s\\Data\\font_data.xml"       },
    { "Data\\skeleton_bodies.xml",     "Modules\\%s\\Data\\skeleton_bodies.xml" },

    { "Data\\flora_kinds.txt",         "Modules\\%s\\Data\\flora_kinds.txt"     },
    { "Data\\ground_specs.txt",        "Modules\\%s\\Data\\ground_specs.txt"    },
    { "Data\\item_modifiers.txt",      "Modules\\%s\\Data\\item_modifiers.txt"  },
    { "Data\\skyboxes.txt",            "Modules\\%s\\Data\\skyboxes.txt"        },

    /* The Last Days -- custom asm pixel shaders, hell yeah! */
    { "man_alpha.pp",                  "Modules\\%s\\Data\\man_alpha.pp"        },
    { "man_basic.pp",                  "Modules\\%s\\Data\\man_basic.pp"        },
    { "man_flora.pp",                  "Modules\\%s\\Data\\man_flora.pp"        },
    { "man_plain.pp",                  "Modules\\%s\\Data\\man_plain.pp"        },
    { "specular.pp",                   "Modules\\%s\\Data\\specular.pp"         },

    { "CommonRes\\core_shaders.brf",   "Modules\\%s\\Data\\core_shaders.brf"    },
    { "CommonRes\\core_textures.brf",  "Modules\\%s\\Data\\core_textures.brf"   },
    { "CommonRes\\core_materials.brf", "Modules\\%s\\Data\\core_materials.brf"  },
    { "CommonRes\\core_ui_meshes.brf", "Modules\\%s\\Data\\core_ui_meshes.brf"  },
    { "CommonRes\\core_pictures.brf",  "Modules\\%s\\Data\\core_pictures.brf"   },
    { NULL, NULL }
  };
     
  char *mod_name = get_current_mod_name();
  
  int i;
  for(i=0;i<sizeof(search_locations);i++)
  { 
    if (search_locations[i].src == 0) break;
  
    //if(strncmp(lpFileName, search_locations[i].src, sizeof(search_locations[i].src))==0)
    if(stricmp(strstr(lpFileName,search_locations[i].src), search_locations[i].src)==0)
    {
      char modded[300];
      sprintf(modded, search_locations[i].dst, mod_name);
      
      char debug[400]; sprintf(debug,  "  |  cool, found a modular replacement candidate: %s", lpFileName);
      il_log(WARN,debug);
      
      if(FileExists(modded))
      {
        lpFileName = modded;
        
        MessageBoxA(0, modded, "match", 0);
        sprintf(debug,  "  |    the replacement file exists, replacing by: %s", modded);
        il_log(WARN,debug);
      }
      
      else
      {
        il_log(ERRO, "  |    the replacement file doesn't seem to exist in the mod... :(");
      }
    }
  }

  return CreateFile(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
  );
}

void il_hook_module(HMODULE *target_module)
{
  IMAGE_DOS_HEADER *dos_header = (PIMAGE_DOS_HEADER)target_module;
  IMAGE_NT_HEADERS *nt_header  = (PIMAGE_NT_HEADERS)((BYTE*)dos_header + (dos_header->e_lfanew));
  IMAGE_OPTIONAL_HEADER IOH    = nt_header -> OptionalHeader;
  
  IMAGE_IMPORT_DESCRIPTOR *imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dos_header + (nt_header-> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

  if (imp==0)
  {
    il_log(ERRO,"looks like the module doesn't have an import table, bailing out... :(");
    return;
  }
  
  TCHAR image_name [MAX_PATH + 1];
  GetModuleFileName(target_module, &image_name, MAX_PATH);
  
  char debug[50];
  sprintf(debug, "image name: %s image base: %x, import virtualaddr: %x first thunk: %x",
                  image_name,
                  nt_header-> OptionalHeader.ImageBase,
                  nt_header-> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                  imp->FirstThunk
  );
  il_log(WARN, "--");
  il_log(WARN, debug);

  while(1)
  {
    if (imp->OriginalFirstThunk == 0) break;
    
    sprintf(debug,"import name: %s, first thunk: %x",
                  (BYTE*)dos_header + imp->Name, imp->FirstThunk
    );
    il_log(INFO, debug);
    
    IMAGE_THUNK_DATA *imp_name_table = (PIMAGE_THUNK_DATA)((BYTE*)dos_header + (imp->OriginalFirstThunk));
    IMAGE_THUNK_DATA *imp_addr_table = (PIMAGE_THUNK_DATA)((BYTE*)dos_header + (imp->FirstThunk));
    
    while(1)
    {
      if (imp_name_table-> u1.AddressOfData == 0) break;
      
      char *imp_name = "Dummy";
      char ordinal[140];
      
      if (imp_name_table-> u1.ForwarderString & (1<<31)) //IMAGE_ORDINAL_FLAG32
      {
        sprintf(ordinal, "ordinal #%u",
                          imp_name_table-> u1.ForwarderString & ~(1<<31)
        );
        imp_name = &ordinal;
      }
      
      else
      {
        imp_name = (BYTE*)dos_header + (imp_name_table-> u1.ForwarderString + 2);
      }
        
      sprintf(debug, "  int: %s/%x, iat: %x",
                     imp_name,
                (int)imp_name_table-> u1.ForwarderString,
                     imp_addr_table-> u1.AddressOfData
      );
      il_log(INFO, debug);
      
      
      if(strncmp(imp_name, "CreateFileA", 11) == 0)
      {        
        sprintf(debug, "  |    hooking iat p: %p / addr: %x  -- hook addr: %x",
                       imp_addr_table->u1.AddressOfData,
                       imp_addr_table->u1.AddressOfData,
                       il_CreateFile);
        il_log(WARN, debug);
        
        DWORD oldProtection;
        if(VirtualProtect(&imp_addr_table->u1.AddressOfData, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtection))
        {
           imp_addr_table->u1.AddressOfData = (DWORD)il_CreateFile;
           il_log(WARN,"  |    API function hooked!");
        }
        
      }

      imp_name_table++;
      imp_addr_table++;
    }
    
    
    imp++;
  }
}



void il_configure_hooks(void)
{
  il_log(INFO, "thread started");
  

  /* for hooking the main game resources (core_*.brf, *.txt, *.xml, ...) */
  il_hook_module(GetModuleHandle(NULL)); //0x400000;
  
  /* for hooking the pixel shaders (*.pp) */
  il_hook_module(GetModuleHandle("d3dx9_31.dll"));
  
  
  
  #ifndef TRUE
  char buffer[50];
  
  //HMODULE handle = GetModuleHandle("SkinMagic.dll");
    
  //sprintf(buffer,"SkinMagic.dll: %x",handle);

  
  //MessageBoxA(0, buffer, "match", 0);

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
      //MessageBoxA(0, msg, orig_path, 0);
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