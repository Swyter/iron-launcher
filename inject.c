#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN

#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>

#include "inject_log_helper.h"

#ifndef E_FAIL
#define E_FAIL 0x80004005
#endif
#define DI_OK 5

/* Global variables */
char  orig_path[MAX_PATH];
char mod_string[MAX_PATH];

char *get_current_mod_name(void)
{
  /* looks fancier with a call, even it it's just a shim after the registry-calling code got removed */
  return &mod_string;
}

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
){

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
    { ".\\man_alpha.pp",               "Modules\\%s\\Data\\man_alpha.pp"        },
    { ".\\man_basic.pp",               "Modules\\%s\\Data\\man_basic.pp"        },
    { ".\\man_flora.pp",               "Modules\\%s\\Data\\man_flora.pp"        },
    { ".\\man_plain.pp",               "Modules\\%s\\Data\\man_plain.pp"        },
    { ".\\specular.pp",                "Modules\\%s\\Data\\specular.pp"         },

    { "CommonRes\\core_shaders.brf",   "Modules\\%s\\Data\\core_shaders.brf"    },
    { "CommonRes\\core_textures.brf",  "Modules\\%s\\Data\\core_textures.brf"   },
    { "CommonRes\\core_materials.brf", "Modules\\%s\\Data\\core_materials.brf"  },
    { "CommonRes\\core_ui_meshes.brf", "Modules\\%s\\Data\\core_ui_meshes.brf"  },
    { "CommonRes\\core_pictures.brf",  "Modules\\%s\\Data\\core_pictures.brf"   },
    { NULL, NULL }
  };
     
  char *mod_name = get_current_mod_name();
  
  /* just in case, if the provided path is not relative */
  char *target_path = (char*)lpFileName;
  
  if(!PathIsRelative(lpFileName))
  {

    /* get the absolute path of the parent executable */
    // R:\Juegos\swconquest\mount&blade.mapedit.exe
    
    TCHAR parent_path[MAX_PATH + 1];
    GetModuleFileName(NULL, parent_path, MAX_PATH);
    
    
    /* strip the filename out of it, leaving just the root M&B folder */
    // R:\Juegos\swconquest
    
    PathRemoveFileSpec(parent_path);
    
    
    /* make target path relative to compare against our needle, this is a problem mainly with d3dx9_31.dll */
    // R:\Juegos\swconquest
    // R:\Juegos\swconquest\specular.pp
    // =
    // .\specular.pp
    
    TCHAR rel_target_path[MAX_PATH + 1] = {0};
    
    BOOL ret = PathRelativePathTo(rel_target_path,
      
                                  parent_path,
                                  FILE_ATTRIBUTE_DIRECTORY,
                                  
                                  lpFileName,
                                  FILE_ATTRIBUTE_NORMAL
    );
    
    /* if the paths are in the same drive and doesn't fails for arcane reasons */
    if(ret == TRUE)
    {
      /* let's be practical, set it as if nothing had happened */
      target_path = rel_target_path;
    }
  }
  
  int i;
  for(i=0;i<sizeof(search_locations);i++)
  { 
    if (search_locations[i].src == 0) break;
    
    
    /* case-insensitive comparison of the requested file against possible modular matches */
    if(stricmp(target_path, search_locations[i].src)==0)
    {
      /* format the module name into it */
      char modded[300];
      sprintf(modded, search_locations[i].dst, mod_name);
      
      char debug[400]; sprintf(debug,  "  |  cool, found a modular replacement candidate: %s", lpFileName);
      il_log(WARN,debug);
      
      if(FileExists(modded))
      {
        /* replace it by our modular alternative, if exists */
        lpFileName = modded;
        
        //MessageBoxA(0, modded, "match", 0);
        sprintf(debug,  "  |    the replacement file exists, replacing by: %s", modded);
        il_log(WARN,debug);
        
        break;
      }
      
      else
      {
        il_log(ERRO, "  |    the replacement file doesn't seem to exist in the mod... :(");
      }
    }
  }
  
  /* call the original function with our tweaks applied, hopefully without much overhead */
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

BOOL __stdcall il_CreateProcess(
  LPCTSTR lpApplicationName,
   LPTSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
     BOOL bInheritHandles,
    DWORD dwCreationFlags,
   LPVOID lpEnvironment,
  LPCTSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
){
  if(strncmp(lpApplicationName,"binkplay.exe",12)==0)
  {
    char *mod_name = get_current_mod_name();
    char  bik_path[MAX_PATH] = {0};
    
    sprintf(bik_path, "Modules\\%s\\Data\\TLDintro.bik", mod_name);

    if(FileExists(bik_path))
    {
      il_log(WARN, "found custom Data\\TLDintro.bik video, skipping TW splash videos...");
      return FALSE;
    }
  }

  return CreateProcess(
          lpApplicationName,
          lpCommandLine,
          lpProcessAttributes,
          lpThreadAttributes,
          bInheritHandles,
          dwCreationFlags,
          lpEnvironment,
          lpCurrentDirectory,
          lpStartupInfo,
          lpProcessInformation
  );
}

LONG __stdcall il_RegSetValueEx(
  HKEY hKey,
  LPCTSTR lpValueName,
  DWORD Reserved,
  DWORD dwType,
  const BYTE *lpData,
  DWORD cbData
){

  if(strstr(lpValueName,"last_module"))
  {
    char debug[400]; sprintf(debug,  "called RegSetValue with value: %s  data: %s", lpValueName, lpData);
    il_log(ERRO, debug);
    
    /* copy the current module name into a local buffer, a bit more permanent */
    strcpy(mod_string, lpData);
  }
  
  /* --- */
  
  char *mod_name = get_current_mod_name();
  char  bik_path[MAX_PATH] = {0};
  
  sprintf(bik_path, "Modules\\%s\\Data\\TLDintro.bik", mod_name);
  
  if(FileExists(bik_path))
  {
    /* append the parameters for the TLD video, fullscreen, no borders, respect aspect ratio */
    strcat(bik_path, " /P /I2 /J /Z /R /U1 /C /B2");

    
    /* launch the TLD custom video, doesn't blocks the main thread, we'll be background-loading in the meantime */
    // Modules\\tld-svn\\Data\\TLDintro.bik /P /I2 /J /Z1 /R /U1 /W-1 /H-1 /C /B2
    #define SEE_MASK_DEFAULT 0x00000000
    #define SEE_MASK_NOASYNC 0x00000100
    #define SEE_MASK_WAITFORINPUTIDLE 0x02000000
    
    SHELLEXECUTEINFO sei =
    {
      .cbSize       = sizeof(SHELLEXECUTEINFO),
      .fMask        = SEE_MASK_DEFAULT|SEE_MASK_NOCLOSEPROCESS,
      .lpVerb       = "open",
      .lpFile       = "binkplay.exe",
      .lpParameters = bik_path,
      .nShow        = SW_SHOW
    };
    
    HINSTANCE video = ShellExecuteEx(&sei);
    WaitForSingleObject(sei.hProcess, INFINITE);
    
    char  dbg[MAX_PATH] = {0};
    sprintf(dbg, "shellexec returns %d, hprocess is: %d", video, sei.hProcess);
    MessageBoxA(NULL,dbg,NULL,NULL);
    
    Sleep(500);
    
    /* keep showing the video even after the game has started, nifty tricks */
    HWND hWnd = FindWindow("BinkWin", NULL);
    
    if(hWnd)
    {
      //MessageBoxA(0,"handle found",0,0);
      SetWindowPos(
        hWnd,
        HWND_TOPMOST,
        0,
        0,
        0,
        0,
        SWP_SHOWWINDOW|SWP_NOSIZE|SWP_NOMOVE
      );
    }
    
    
    
    // DWORD WINAPI SuspendThread(
      // main_thread
    // );
    
    // WaitForSingleObject(video, INFINITE);
    
    // DWORD WINAPI ResumeThread(
      // main_thread
    // );
    
    il_log(WARN, "found and played custom Data\\TLDintro.bik video... enjoy it!");
  }
  
  /* --- */
  
  return RegSetValueEx(
          hKey,
          lpValueName,
          Reserved,
          dwType,
          lpData,
          cbData
  );
}

void il_hook_module(HINSTANCE target_module)
{
  if (target_module==0)
  {
    il_log(ERRO,"--");
    il_log(ERRO,"looks like the module doesn't exists, bailing out... :(");
    return;
  }


  IMAGE_DOS_HEADER *dos_header = (PIMAGE_DOS_HEADER)target_module;
  IMAGE_NT_HEADERS *nt_header  = (PIMAGE_NT_HEADERS)((BYTE*)dos_header + (dos_header->e_lfanew));
  
  IMAGE_IMPORT_DESCRIPTOR *imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dos_header + (nt_header-> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

  if (imp==0)
  {
    il_log(ERRO,"looks like the module doesn't have an import table, bailing out... :(");
    return;
  }
  
  TCHAR image_name [MAX_PATH + 1];
  GetModuleFileName(target_module, image_name, MAX_PATH);
  
  char debug[50];
  sprintf(debug, "image name: %s image base: %x, import virtualaddr: %x first thunk: %x",
                  image_name,
                  nt_header-> OptionalHeader.ImageBase,
                  nt_header-> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                  imp->FirstThunk
  );
  il_log(WARN, "--");
  il_log(WARN, debug);

  
  /* loop for all the imported DLLs */
  while(1)
  {
    if (imp->OriginalFirstThunk == 0) break;
    
    sprintf(debug,"import name: %s, first thunk: %x",
                  (BYTE*)dos_header + imp->Name, imp->FirstThunk
    );
    il_log(INFO, debug);
    
    IMAGE_THUNK_DATA *imp_name_table = (PIMAGE_THUNK_DATA)((BYTE*)dos_header + (imp->OriginalFirstThunk));
    IMAGE_THUNK_DATA *imp_addr_table = (PIMAGE_THUNK_DATA)((BYTE*)dos_header + (imp->FirstThunk));
    
    /* loop for all the imported functions in the parallel sibling structures (INT and IAT) from every DLL */
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
        imp_name = (char*)ordinal;
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
      
      
      /* let's make an array with all the hooks to be deployed, this was getting out of hand */
      
      static struct{const char *import_name; DWORD function_addr;} il_hooks[] =
      {
        { "CreateFileA",    il_CreateFile    },
        { "CreateProcessA", il_CreateProcess },
        { "RegSetValueExA", il_RegSetValueEx },
        { NULL, NULL }
      };
      
      /* and process them automatically in a loop, more or less */
      
      int i;
      for(i=0;i<sizeof(il_hooks);i++)
      {
        /* break on the final NULL marker, because hell yeah! */
        if (il_hooks[i].import_name == 0) break;
        
        /* see if the current import and any of the names match */
        if(strcmp(imp_name, il_hooks[i].import_name) == 0)
        {
          sprintf(debug, "  |    hooking iat p: %p / addr: %x  -- hook addr: %x",
                         &imp_addr_table->u1.AddressOfData,
                          imp_addr_table->u1.AddressOfData,
                          il_hooks[i].function_addr);
          il_log(WARN, debug);
          
          DWORD oldProtection;
          if(VirtualProtect(&imp_addr_table->u1.AddressOfData, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtection))
          {
             /* if the memory got unprotected, overwrite the IAT address */
             imp_addr_table->u1.AddressOfData = il_hooks[i].function_addr;
             il_log(WARN,"  |    API function hooked!");
          }
          
          else
          {
             il_log(ERRO,"  |    unable to unprotect memory, great!");
          }
          
          break;
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
  
  /* for hooking the pixel shaders (*.pp) -- 1.011 */
  il_hook_module(GetModuleHandle("d3dx9_31.dll"));
  
  /* for hooking the pixel shaders (*.pp) -- wb */
  il_hook_module(GetModuleHandle("d3dx9_42.dll")); 
  
  
  il_log(INFO, "thread ended, now wait for the hooked calls...");
  return;

}


int __stdcall DirectInput8Create(int a1, int a2, int a3, int a4, int a5)
{
  int result;
  
  /* Find out where %windir%\\system32 is and append the real DLL filename */
  GetSystemDirectoryA((LPSTR)orig_path, MAX_PATH); strcat((LPSTR)orig_path, "\\dinput8.dll");

  /* Get the native function and proxy it */
  HINSTANCE orig_handle = LoadLibraryA((LPSTR)orig_path);
  FARPROC   orig_pointer;
  
  if (orig_handle && (orig_pointer = GetProcAddress(orig_handle, "DirectInput8Create")) != 0 )
    result = ((int (__stdcall *)(int, int, int, int, int))orig_pointer)(a1, a2, a3, a4, a5);
    
  else
    result = E_FAIL;
    
  /* Print a debug messagebox with call-related info */
  char msg[MAX_PATH]; sprintf(msg,"DirectInput8Create called -- result: %x params: /%x/%x/%x/%p/%x/  orig entrypoint: %x/ from native dinput8 loaded at %x",
                              result, a1, a2, a3, a4, a4, orig_pointer, orig_handle);
  
  il_log(WARN, msg);
  return result;
}

BOOL __stdcall DllMain(
  HINSTANCE hModule,
      DWORD ulReason,
     LPVOID lpReserved
){
  switch(ulReason)
  {
    /* If we are attaching to a process */
    case DLL_PROCESS_ATTACH:

      /* We don't need the thread based attach/detach messages in this DLL */
      DisableThreadLibraryCalls(hModule);
      
      /* Get the module handles and paths for the parent executable and itself */
      TCHAR parent_path [MAX_PATH + 1];
      GetModuleFileName(NULL, (LPSTR)&parent_path, MAX_PATH);
      
      HINSTANCE parent_handle = GetModuleHandle(NULL);
      HINSTANCE self_handle   = hModule;
      
      TCHAR self_path [MAX_PATH + 1];
      GetModuleFileName(self_handle, (LPSTR)&self_path, MAX_PATH);
      
      /* Print a debug messagebox with parent-related info */
      char msg[MAX_PATH]; sprintf(msg,"parent exe path: %s \n"
                                  "    parent exe handle: %p \n"
                                  "    dll self handle: %p \n"
                                  "    dll self path: %s \n", parent_path, parent_handle, self_handle, self_path);
      il_log(INFO, msg);
      
      /* Do the rest of the stuff in a new thread to avoid blocking the entire program */
      HANDLE threat_id = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)il_configure_hooks,
        NULL,
        (DWORD)NULL,
        0//'IL'
      );
      
      if(threat_id)
        SetThreadPriority(threat_id, THREAD_PRIORITY_TIME_CRITICAL);      
      else
        il_log(ERRO,"looks like the thread where all the important bits "
                    "happen couldn't be started somehow... now that's unexpected!");
      
      break;

    /* If the process asks for unloading */
    case DLL_PROCESS_DETACH:
    
      // MessageBoxA(0, "unloading!", (LPSTR)&orig_path, 0);
      break;
  }

  /* Signal for Loading/Unloading */
  return (TRUE);
}