@echo off
rem %1 = full target path
rem %2 = last two digits of the Visual Studio version number (e.g. 17)
rem %3 = targetname suffix (e.g. -sandybridge,  _static, -sandybridge_static...)

set vs_ver=%2
set str=%~1
set suffix=%~3

rem delete anything from the path before the FINAL 'msvc'
:dele
set str=%str:~1%
set str2=%str:~0,4%

if "%str%" EQU "" (
  goto dele_done
) else if "%str2%" EQU "msvc" (
  set str_confirmed=%str%
)
goto dele
:dele_done
set str=%str_confirmed%
echo "Final subpath %str%"

rem we now have: msvc.\vs<nn>\<project_directory>\<win32|x64>\<debug|release>\mpir.<lib|dll>
rem extract: project_directory, platform (plat=<win32|x64>), configuration (conf=<debug|release>) and file name

set file=
for /f "tokens=1,2,3,4,5,6 delims=\" %%a in ("%str%") do set tloc=%%c&set plat=%%d&set conf=%%e&set file=%%f
if /i "%file%" NEQ "" (goto next)
call :seterr & echo ERROR: %1 is not supported & exit /b %errorlevel%

:next
echo target=%tloc%, platform=%plat%, configuration=%conf%, file=%file%

rem get the filename extension (lib/dll) to set the output directory
set loc=%tloc%\
set extn=%file%#
set filename=%extn:~0,-5%
set extn=%extn:~-4,3%
if "%extn%" EQU "lib" (goto is2nd)
if "%extn%" EQU "dll" (goto is2nd)
call :seterr & echo "postbuild copy error ERROR: target=%tloc%, plat=%plat%, conf=%conf%, file=%file%, filename=%filename%, extn=%extn%" & exit /b %errorlevel%

:is2nd:
rem set the target and final binary output directories
set tgt_dir="vs%vs_ver%\%loc%%plat%\%conf%\"
set out_dir="..\build\vs%vs_ver%-%plat%_%conf%%suffix:_static=%\"
echo %out_dir%

rem output parametrers for the MPIR tests
if /i "%filename%" EQU "mpir-xx" goto skip
echo (set ldir=%loc%)   > output_params.bat
echo (set libr=%extn%) >> output_params.bat
echo (set plat=%plat%) >> output_params.bat
echo (set conf=%conf%) >> output_params.bat
:skip

echo copying outputs from %tgt_dir% to %out_dir%
if not exist %out_dir%bin md %out_dir%bin
if not exist %out_dir%lib md %out_dir%lib
if not exist %out_dir%include md %out_dir%include
call :copyh %tgt_dir%
call :copyh %out_dir%include\
call :copyb %tgt_dir% %out_dir% %conf% %extn% %filename% %suffix%
exit /b 0

rem copy binaries to final out_dir destination directory
rem %1 = target (build output) directory
rem %2 = binary destination directory
rem %3 = configuration (debug/release)
rem %4 = library (lib/dll)
rem %5 = file name
rem %6 = targetname suffix (e.g. -sandybridge,  _static, -sandybridge_static...)
:copyb
if "%4" EQU "dll" (
	copy %1mpir%6.dll %2bin\mpir%6.dll > nul 2>&1
REM	copy %1mpir%6.exp %2mpir%6.exp > nul 2>&1
	copy %1mpir%6.lib %2lib\mpir%6.lib > nul 2>&1
	if exist %1mpir%6.pdb (copy %1mpir%6.pdb %2bin\mpir%6.pdb  > nul 2>&1)
) else if "%4" EQU "lib" (
  	    if exist %1%5.lib (copy %1%5.lib %2lib\%5.lib > nul 2>&1)
	    if exist %1%5.pdb (copy %1%5.pdb %2lib\%5.pdb > nul 2>&1)
) else (
	call :seterr & echo ERROR: illegal library type %4  & exit /b %errorlevel%
)

rem set configuration for the tests
call gen_test_config_props %plat% %conf% %vs_ver%
exit /b 0

rem copy headers to final destination directory
:copyh
REM exclude copy of 'config.h' 
for %%H in (gmp-mparam mpir gmp-impl longlong mpirxx) do (copy ..\%%H.h %1%%H.h > nul 2>&1)
copy ..\mpir.h %1gmp.h > nul 2>&1
copy ..\mpirxx.h %1gmpxx.h > nul 2>&1
exit /b 0

:seterr
exit /b 1
