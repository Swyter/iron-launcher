#include <stdio.h>

enum{
  INFO,
  WARN,
  ERRO
} e_log_level;

FILE *il_log_file;

void il_log(int log_level, char *msg)
{
  if(!il_log_file)
  {
    il_log_file = fopen("dinput8.dll.il.log","w+");
  }
  
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