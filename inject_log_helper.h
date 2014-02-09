#include <stdio.h>
#include "inject_date.h"

enum{
  INFO,
  WARN,
  ERRO
} e_log_level;

FILE *il_log_file;

void il_log(int log_level, char *msg)
{

  /* if this is the first time the logging function has been called */
  if(!il_log_file)
  {
    if(il_log_file = fopen("dinput8.dll.il.log","w+"))
    {
      /* a warm welcome is always worthwhile, i don't know why fputs gives problems here */
      fprintf(il_log_file, "--- Welcome to Iron Launcher " DATE_str ".1337\n"
                           "--- have a nice day!\n\n");
      fflush(il_log_file);
    }
  }
  
  /* let's cover our common ass and try to not crash on loader initialization if the filesystem is read-only or protected */
  if(il_log_file)
  {
    char *symbol;
    
    switch(log_level)
    {
      case INFO: symbol = (char*)'I'; break;
      case WARN: symbol = (char*)'!'; break;
      case ERRO: symbol = (char*)'E'; break;
      default:   symbol = (char*)' ';
    }
    
    fprintf(il_log_file,"[%c] %s\n", symbol, msg); fflush(il_log_file);
  }
}