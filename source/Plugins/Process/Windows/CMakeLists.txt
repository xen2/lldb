set(LLVM_NO_RTTI 1)

include_directories(.)
include_directories(../Utility)

add_lldb_library(lldbPluginProcessWindows
  ProcessWindows.cpp
  ThreadWindows.cpp
  RegisterContextWindows_i386.cpp
  RegisterContextWindowsDebug_i386.cpp
  )
