@echo off && title comp && set dvd=%cd%
:top
	echo -- compiling resources        && echo #define DATE %date:~-4%,%date:~-7,2%,%date:~,2% > inject_date.rc
	                                      windres inject.rc -o inject.rc.o
	echo -- compiling injector thingie && gcc inject.c inject.def inject.rc.o -s -shared -o dinput8.dll -lshlwapi && rem -Wl,-enable-stdcall-fixup
	                                      if %errorlevel% geq 1 goto :finish
	echo -- copying to the mab folder  && copy dinput8.dll ..\..\Juegos\swconquest\
	echo -- running the game           && cd ..\..\Juegos\swconquest && mount^&blade.mapedit.exe
	echo -- getting log                && type dinput8.dll.il.log
	                                      cd %dvd% && rem ..\..\Repositories\iron-launcher
	                                      :finish
	                                      pause && echo. && echo. && goto :top