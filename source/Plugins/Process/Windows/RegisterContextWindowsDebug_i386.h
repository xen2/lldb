//===-- RegisterContextWindowsDebug_i386.h ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContextDebug_i386_h_
#define liblldb_RegisterContextDebug_i386_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Core/Log.h"
#include "RegisterContextPOSIX_x86.h"

class RegisterContextWindowsDebug_i386 : public RegisterContextPOSIX_x86, public POSIXBreakpointProtocol
{
public:
    RegisterContextWindowsDebug_i386(lldb_private::Thread &thread,
                              uint32_t concreate_frame_idx,
                              RegisterInfoInterface *register_info);

    ~RegisterContextWindowsDebug_i386();

    // lldb_private::RegisterContext
    bool
    ReadRegister(const unsigned reg, lldb_private::RegisterValue &value);

    bool
    WriteRegister(const unsigned reg, const lldb_private::RegisterValue &value);

    bool
    ReadRegister(const lldb_private::RegisterInfo *reg_info, lldb_private::RegisterValue &value);

    bool
    WriteRegister(const lldb_private::RegisterInfo *reg_info, const lldb_private::RegisterValue &value);

    bool
    ReadAllRegisterValues(lldb::DataBufferSP &data_sp);

    bool
    HardwareSingleStep(bool enable);

protected:
    bool
    ReadGPR();

    bool
    ReadFPR();

    bool
    WriteGPR();

    bool
    WriteFPR();

    // POSIXBreakpointProtocol
    bool
    UpdateAfterBreakpoint();

    unsigned
    GetRegisterIndexFromOffset(unsigned offset);

    bool
    IsWatchpointHit(uint32_t hw_index);

    bool
    ClearWatchpointHits();

    lldb::addr_t
    GetWatchpointAddress(uint32_t hw_index);

    bool
    IsWatchpointVacant(uint32_t hw_index);

    bool
    SetHardwareWatchpointWithIndex(lldb::addr_t addr, size_t size, bool read, bool write, uint32_t hw_index);

    uint32_t
    NumSupportedHardwareWatchpoints();

private:
    CONTEXT context;
};

#endif // #ifndef liblldb_RegisterContext_i386_h_
