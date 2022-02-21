
# returns:
#   solution file version
#   visual studio version
#   microsoft compiler version
#   microsoft compiler version (long)
#   vcx project tools version
#   windows SDK version
vs_info = { 'vs_dir':'22',                    # current vsXX directory
            'solution':'12',                  # sln: Microsoft Visual Studio Solution File, Format Version __VERSION__.00
            'visual studio':'17',             # sln: Visual Studio __VERSION__
            'msvc':'14',                      # sln:   if > 12 print 'vs_long'
            'vs_long':'17.2.32210.308',       # sln: VisualStudioVersion __VERSION__
            'vcx_tool':'14.32.31114',         # vcxproj: <Project ToolsVersion="__VERSION__" -- %MSVS_INSTALL_PATH%\Community\VC\Tools\__VERSION__
            'platform_toolset':'143',         # vcxproj: <PlatformToolset>__VERSION__
            'windows_sdk':'10.0.22000.0'      # vcxproj: <WindowsTargetPlatformVersion>__VERSION__ -- %WK_INSTALL_PATH%\10\Include\__VERSION__
            # Windows 10 (latest installed)
            # 'windows_sdk':'10.0.17763.0'    # Windows 10 version 1809
            # 'windows_sdk':'10.0.17134.0'    # Windows 10 version 1803
            # 'windows_sdk':'10.0.16299.0'    # Windows 10 Creators Update
            # 'windows_sdk':'10.0.14393.795'  # Windows 10
          }
