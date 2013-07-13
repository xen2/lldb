//===-- RegisterContextWindows_i386.h ---------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContext_i386_h_
#define liblldb_RegisterContext_i386_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Core/Log.h"
#include "RegisterContextPOSIX_x86.h"

class RegisterContextWindows_i386
  : public RegisterInfoInterface
{
public:
    RegisterContextWindows_i386(const lldb_private::ArchSpec &target_arch);
    virtual ~RegisterContextWindows_i386();

    size_t
    GetGPRSize();

    const lldb_private::RegisterInfo *
    GetRegisterInfo();
};

#endif // #ifndef liblldb_RegisterContext_i386_h_
