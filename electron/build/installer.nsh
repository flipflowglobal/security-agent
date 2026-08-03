; Override default install directory to the current user's Desktop.
; Runs inside .onInit via the electron-builder `customInit` hook, after
; initMultiUser so this assignment is authoritative.
!macro customInit
  SetShellVarContext current
  StrCpy $INSTDIR "$DESKTOP\Security-Agent"
!macroend
