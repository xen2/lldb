//===-- RegisterContextWindowsDebug_i386.cpp --------------------*- C++ -*-===//
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
#include "RegisterContextWindowsDebug_i386.h"

#include "ThreadWindows.h"

using namespace lldb_private;
using namespace lldb;

static uint32_t
size_and_rw_bits(size_t size, bool read, bool write)
{
    uint32_t rw;

    if (read)
        rw = 0x3; // READ or READ/WRITE
    else if (write)
        rw = 0x1; // WRITE
    else
        assert(0 && "read and write cannot both be false");

    switch (size)
    {
    case 1:
        return rw;
    case 2:
        return (0x1 << 2) | rw;
    case 4:
        return (0x3 << 2) | rw;
    case 8:
        return (0x2 << 2) | rw;
    default:
        assert(0 && "invalid size, must be one of 1, 2, 4, or 8");
    }
}

RegisterContextWindowsDebug_i386::RegisterContextWindowsDebug_i386(Thread &thread,
                                                     uint32_t concrete_frame_idx,
                                                     RegisterInfoInterface *register_info)
    : RegisterContextPOSIX_x86(thread, concrete_frame_idx, register_info)
{
    context.ContextFlags = CONTEXT_FULL;
}

RegisterContextWindowsDebug_i386::~RegisterContextWindowsDebug_i386()
{
}

bool
RegisterContextWindowsDebug_i386::ReadRegister(const unsigned reg, RegisterValue &value)
{
    return false;
}

bool
RegisterContextWindowsDebug_i386::ReadRegister(const RegisterInfo *reg_info,
                                        RegisterValue &value)
{
    // For now it just fetch full context for every register
    // TODO: Optimized version, only fetch and set what's necessary, when necessary
    ThreadWindows& thread = static_cast<ThreadWindows&>(m_thread);
    if (!GetThreadContext(thread.GetHandle(), &context))
        return false;

    switch (reg_info->byte_size)
    {
    case 4:
        value = *(uint32_t *) ((uint8_t*)&context + reg_info->byte_offset);
        return true;
    case 8:
        value = *(uint64_t *) ((uint8_t*)&context + reg_info->byte_offset);
        return true;
    }
    return false;
}

bool
RegisterContextWindowsDebug_i386::ReadAllRegisterValues(DataBufferSP &data_sp)
{
    return false;
}

bool
RegisterContextWindowsDebug_i386::WriteRegister(const unsigned reg, const RegisterValue &value)
{
    return false;
}

bool RegisterContextWindowsDebug_i386::WriteRegister(const RegisterInfo *reg_info,
                                         const RegisterValue &value)
{
    // For now it just fetch full context for every register
    // TODO: Optimized version, only fetch and set what's necessary, when necessary
    ThreadWindows& thread = static_cast<ThreadWindows&>(m_thread);
    if (!GetThreadContext(thread.GetHandle(), &context))
        return false;

    switch (reg_info->byte_size)
    {
    case 4:
        *(uint32_t *) ((uint8_t*)&context + reg_info->byte_offset) = value.GetAsUInt32();
    case 8:
        *(uint64_t *) ((uint8_t*)&context + reg_info->byte_offset) = value.GetAsUInt64();
    }

    if (!SetThreadContext(thread.GetHandle(), &context))
        return false;

    return true;
}

bool
RegisterContextWindowsDebug_i386::UpdateAfterBreakpoint()
{
    // PC points one byte past the int3 responsible for the breakpoint.
    lldb::addr_t pc;

    if ((pc = GetPC()) == LLDB_INVALID_ADDRESS)
        return false;

    // Only reset PC to int3 address if it's a known LLDB breakpoint site.
    // User or system (DebugBreakProcess) int3 should be kept as is.
    if (m_thread.GetProcess()->GetBreakpointSiteList().FindByAddress(pc - 1)
        || (((ThreadWindows&)m_thread).m_breakpoint && ((ThreadWindows&)m_thread).m_breakpoint->GetLoadAddress() == pc - 1))
        SetPC(pc - 1);
    return true;
}

bool
RegisterContextWindowsDebug_i386::HardwareSingleStep(bool enable)
{
    enum { TRACE_BIT = 0x100 };
    uint64_t eflags;

    if ((eflags = ReadRegisterAsUnsigned(gpr_eflags_i386, -1UL)) == -1UL)
        return false;

    if (enable)
    {
        if (eflags & TRACE_BIT)
            return true;

        eflags |= TRACE_BIT;
    }
    else
    {
        if (!(eflags & TRACE_BIT))
            return false;

        eflags &= ~TRACE_BIT;
    }

    return WriteRegisterFromUnsigned(gpr_eflags_i386, eflags);
}

bool
RegisterContextWindowsDebug_i386::ReadGPR()
{
    GetThreadContext((HANDLE)m_thread.GetID(), &context);

    return true;
}

bool
RegisterContextWindowsDebug_i386::ReadFPR()
{
    return false;
}

bool
RegisterContextWindowsDebug_i386::WriteGPR()
{
    return false;
}

bool
RegisterContextWindowsDebug_i386::WriteFPR()
{
    return false;
}

unsigned
RegisterContextWindowsDebug_i386::GetRegisterIndexFromOffset(unsigned offset)
{
    unsigned reg;
    for (reg = 0; reg < m_reg_info.num_registers; reg++)
    {
        if (GetRegisterInfo()[reg].byte_offset == offset)
            break;
    }
    assert(reg < m_reg_info.num_registers && "Invalid register offset.");
    return reg;
}

bool
RegisterContextWindowsDebug_i386::IsWatchpointHit(uint32_t hw_index)
{
    bool is_hit = false;

    if (m_watchpoints_initialized == false)
    {
        // Reset the debug status and debug control registers
        RegisterValue zero_bits = RegisterValue(uint64_t(0));
        if (!WriteRegister(m_reg_info.first_dr + 6, zero_bits) || !WriteRegister(m_reg_info.first_dr + 7, zero_bits))
            assert(false && "Could not initialize watchpoint registers");
        m_watchpoints_initialized = true;
    }

    if (hw_index < NumSupportedHardwareWatchpoints())
    {
        RegisterValue value;

        if (ReadRegister(m_reg_info.first_dr + 6, value))
        {
            uint64_t val = value.GetAsUInt64();
            is_hit = val & (1 << hw_index);
        }
    }

    return is_hit;
}

bool
RegisterContextWindowsDebug_i386::ClearWatchpointHits()
{
    return WriteRegister(m_reg_info.first_dr + 6, RegisterValue((uint64_t)0));
}

addr_t
RegisterContextWindowsDebug_i386::GetWatchpointAddress(uint32_t hw_index)
{
    addr_t wp_monitor_addr = LLDB_INVALID_ADDRESS;

    if (hw_index < NumSupportedHardwareWatchpoints())
    {
        if (!IsWatchpointVacant(hw_index))
        {
            RegisterValue value;

            if (ReadRegister(m_reg_info.first_dr + hw_index, value))
                wp_monitor_addr = value.GetAsUInt64();
        }
    }

    return wp_monitor_addr;
}

bool
RegisterContextWindowsDebug_i386::IsWatchpointVacant(uint32_t hw_index)
{
    bool is_vacant = false;
    RegisterValue value;

    assert(hw_index < NumSupportedHardwareWatchpoints());

    if (m_watchpoints_initialized == false)
    {
        // Reset the debug status and debug control registers
        RegisterValue zero_bits = RegisterValue(uint64_t(0));
        if (!WriteRegister(m_reg_info.first_dr + 6, zero_bits) || !WriteRegister(m_reg_info.first_dr + 7, zero_bits))
            assert(false && "Could not initialize watchpoint registers");
        m_watchpoints_initialized = true;
    }

    if (ReadRegister(m_reg_info.first_dr + 7, value))
    {
        uint64_t val = value.GetAsUInt64();
        is_vacant = (val & (3 << 2*hw_index)) == 0;
    }

    return is_vacant;
}

bool
RegisterContextWindowsDebug_i386::SetHardwareWatchpointWithIndex(addr_t addr, size_t size,
                                                       bool read, bool write,
                                                       uint32_t hw_index)
{
    const uint32_t num_hw_watchpoints = NumSupportedHardwareWatchpoints();

    if (num_hw_watchpoints == 0 || hw_index >= num_hw_watchpoints)
        return false;

    if (!(size == 1 || size == 2 || size == 4 || size == 8))
        return false;

    if (read == false && write == false)
        return false;

    if (!IsWatchpointVacant(hw_index))
        return false;

    // Set both dr7 (debug control register) and dri (debug address register).

    // dr7{7-0} encodes the local/global enable bits:
    //  global enable --. .-- local enable
    //                  | |
    //                  v v
    //      dr0 -> bits{1-0}
    //      dr1 -> bits{3-2}
    //      dr2 -> bits{5-4}
    //      dr3 -> bits{7-6}
    //
    // dr7{31-16} encodes the rw/len bits:
    //  b_x+3, b_x+2, b_x+1, b_x
    //      where bits{x+1, x} => rw
    //            0b00: execute, 0b01: write, 0b11: read-or-write,
    //            0b10: io read-or-write (unused)
    //      and bits{x+3, x+2} => len
    //            0b00: 1-byte, 0b01: 2-byte, 0b11: 4-byte, 0b10: 8-byte
    //
    //      dr0 -> bits{19-16}
    //      dr1 -> bits{23-20}
    //      dr2 -> bits{27-24}
    //      dr3 -> bits{31-28}
    if (hw_index < num_hw_watchpoints)
    {
        RegisterValue current_dr7_bits;

        if (ReadRegister(m_reg_info.first_dr + 7, current_dr7_bits))
        {
            uint64_t new_dr7_bits = current_dr7_bits.GetAsUInt64() |
                                    (1 << (2*hw_index) |
                                    size_and_rw_bits(size, read, write) <<
                                    (16+4*hw_index));

            if (WriteRegister(m_reg_info.first_dr + hw_index, RegisterValue(addr)) &&
                WriteRegister(m_reg_info.first_dr + 7, RegisterValue(new_dr7_bits)))
                return true;
        }
    }

    return false;
}

uint32_t
RegisterContextWindowsDebug_i386::NumSupportedHardwareWatchpoints()
{
    // Available debug address registers: dr0, dr1, dr2, dr3
    return 4;
}
