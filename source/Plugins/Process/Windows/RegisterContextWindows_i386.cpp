//===-- RegisterContextWindows_i386.cpp -------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/DataExtractor.h"
#include "lldb/Core/RegisterValue.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/Process.h"
#include "lldb/Host/Endian.h"
#include "lldb/Host/windows/windows.h"

#include "RegisterContextPOSIX_x86.h"
#include "RegisterContextWindows_i386.h"

#include "ThreadWindows.h"

using namespace lldb_private;
using namespace lldb;

struct GPR
{
    DWORD ContextFlags;

    // CONTEXT_DEBUG_REGISTERS
    // No dr4 and dr5, they map to dr6 and dr7
    DWORD   dr[6];

    // CONTEXT_FLOATING_POINT
    FLOATING_SAVE_AREA FloatSave;

    // CONTEXT_SEGMENTS
    DWORD   gs;
    DWORD   fs;
    DWORD   es;
    DWORD   ds;

    // CONTEXT_INTEGER
    DWORD   edi;
    DWORD   esi;
    DWORD   ebx;
    DWORD   edx;
    DWORD   ecx;
    DWORD   eax;

    // CONTEXT_CONTROL
    DWORD   ebp;
    DWORD   eip;
    DWORD   cs;              // MUST BE SANITIZED
    DWORD   eflags;             // MUST BE SANITIZED
    DWORD   esp;
    DWORD   ss;

    // CONTEXT_EXTENDED_REGISTERS
    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
};

#define DR_SIZE sizeof(DWORD)
#define DR_OFFSET(reg_index) \
    (LLVM_EXTENSION offsetof(GPR, dr[reg_index > 6 ? reg_index - 2 : reg_index]))

//---------------------------------------------------------------------------
// Include RegisterInfos_i386 to declare our g_register_infos_i386 structure.
//---------------------------------------------------------------------------
#define DECLARE_REGISTER_INFOS_I386_STRUCT
#include "RegisterInfos_i386.h"
#undef DECLARE_REGISTER_INFOS_I386_STRUCT

RegisterContextWindows_i386::RegisterContextWindows_i386(const ArchSpec &target_arch) :
    RegisterInfoInterface(target_arch)
{
}

RegisterContextWindows_i386::~RegisterContextWindows_i386()
{
}

size_t
RegisterContextWindows_i386::GetGPRSize()
{
    return sizeof(GPR);
}

const RegisterInfo *
RegisterContextWindows_i386::GetRegisterInfo()
{
    switch (m_target_arch.GetMachine())
    {
        case llvm::Triple::x86:
            return g_register_infos_i386;
        default:
            assert(false && "Unhandled target architecture.");
            return NULL;
    }
}
