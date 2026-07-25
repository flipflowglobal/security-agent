!include "FileFunc.nsh"
!insertmacro GetDesktop

; Override default install directory to user's Desktop
StrCpy $INSTDIR "$DESKTOP\Security-Agent"
