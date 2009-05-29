# Microsoft Developer Studio Project File - Name="swill_lib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=swill_lib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "swill.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "swill.mak" CFG="swill_lib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "swill_lib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "swill_lib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "swill_lib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../Source/Objects" /I "../../Source/SWILL" /I "../../Include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D SWILL_DLL=0 /D SWILL_SSL=1 /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "swill_lib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "../../Source/Objects" /I "../../Source/SWILL" /I "../../Include" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D SWILL_DLL=0 /D SWILL_SSL=1 /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "swill_lib - Win32 Release"
# Name "swill_lib - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\Source\Objects\base.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\encoding.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\file.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\fio.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\handlers.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\io.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\list.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\log.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\memory.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\mime.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\parse.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\security.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\sock.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\ssl.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\string.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\void.c
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\web.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\Source\Objects\doh.h
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\dohint.h
# End Source File
# Begin Source File

SOURCE=..\..\Source\Objects\dohobj.h
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\sock.h
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\ssl.h
# End Source File
# Begin Source File

SOURCE=..\..\Include\swill.h
# End Source File
# Begin Source File

SOURCE=..\..\Source\SWILL\swillint.h
# End Source File
# End Group
# End Target
# End Project
