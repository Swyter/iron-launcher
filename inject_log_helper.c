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
    il_log_file = fopen("R:\\Repositories\\iron-launcher-redux\\log.log","w+");
  }
  
  char *symbol;
  
  switch(log_level)
  {
    case INFO: symbol = "I"; break;
    case WARN: symbol = "!"; break;
    case ERRO: symbol = "E"; break;
    default:   symbol = " ";
  }    
  
  fprintf(il_log_file,"[%s] %s", symbol, msg); fflush(il_log_file);
}


int main()
{
  il_log(INFO, "hola");
  
  return 1;
}