//===-- DynamicLoaderWindows.cpp --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
// C++ Includes
// Other libraries and framework includes
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Disassembler.h"
#include "lldb/Core/Log.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Core/Section.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/SectionLoadList.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/ThreadPlanRunToAddress.h"

#include "DynamicLoaderWindows.h"

using namespace lldb;
using namespace lldb_private;

void
DynamicLoaderWindows::Initialize()
{
    PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                  GetPluginDescriptionStatic(),
                                  CreateInstance);
}

void
DynamicLoaderWindows::Terminate()
{
}

lldb_private::ConstString
DynamicLoaderWindows::GetPluginName()
{
    return GetPluginNameStatic();
}

lldb_private::ConstString
DynamicLoaderWindows::GetPluginNameStatic()
{
    static ConstString g_name("windows-dyld");
    return g_name;
}

const char *
DynamicLoaderWindows::GetPluginDescriptionStatic()
{
    return "Dynamic loader plug-in that watches for shared library "
           "loads/unloads in Windows processes.";
}

void
DynamicLoaderWindows::GetPluginCommandHelp(const char *command, Stream *strm)
{
}

uint32_t
DynamicLoaderWindows::GetPluginVersion()
{
    return 1;
}

DynamicLoader *
DynamicLoaderWindows::CreateInstance(Process *process, bool force)
{
    bool create = force;
    if (!create)
    {
        const llvm::Triple &triple_ref = process->GetTarget().GetArchitecture().GetTriple();
        if (triple_ref.getOS() == llvm::Triple::Win32 ||
            triple_ref.getOS() == llvm::Triple::MinGW32)
            create = true;
    }

    if (create)
        return new DynamicLoaderWindows (process);
    return NULL;
}

DynamicLoaderWindows::DynamicLoaderWindows(Process *process)
    : DynamicLoader(process),
      m_load_offset(LLDB_INVALID_ADDRESS),
      m_entry_point(LLDB_INVALID_ADDRESS)
{
}

DynamicLoaderWindows::~DynamicLoaderWindows()
{
}

void
DynamicLoaderWindows::DidAttach()
{
}

void
DynamicLoaderWindows::DidLaunch()
{
}

Error
DynamicLoaderWindows::ExecutePluginCommand(Args &command, Stream *strm)
{
    return Error();
}

Log *
DynamicLoaderWindows::EnablePluginLogging(Stream *strm, Args &command)
{
    return NULL;
}

Error
DynamicLoaderWindows::CanLoadImage()
{
    return Error();
}

ThreadPlanSP
DynamicLoaderWindows::GetStepThroughTrampolinePlan(Thread &thread, bool stop)
{
    ThreadPlanSP thread_plan_sp;

    RegisterContext *reg_ctx = thread.GetRegisterContext().get();

    lldb::addr_t pc = reg_ctx->GetPC();
    ProcessSP process_sp(thread.GetProcess());
    Address pc_addr;
    bool addr_valid = false;
    uint8_t buffer[16] = { 0 }; // Must be big enough for any single instruction
    addr_valid = process_sp->GetTarget().GetSectionLoadList().ResolveLoadAddress(pc, pc_addr);

    // TODO: Cache it as in ThreadPlanAssemblyTracer::GetDisassembler ()
    DisassemblerSP disassembler = Disassembler::FindPlugin(thread.GetProcess()->GetTarget().GetArchitecture(), NULL, NULL);
    if (disassembler)
    {
        Error err;
        process_sp->ReadMemory(pc, buffer, sizeof(buffer), err);

        if (err.Success())
        {
            DataExtractor extractor(buffer, sizeof(buffer),
                process_sp->GetByteOrder(),
                process_sp->GetAddressByteSize());

            bool data_from_file = false;
            if (addr_valid)
                disassembler->DecodeInstructions(pc_addr, extractor, 0, 1, false, data_from_file);
            else
                disassembler->DecodeInstructions(Address(pc), extractor, 0, 1, false, data_from_file);

            InstructionList &instruction_list = disassembler->GetInstructionList();

            if (instruction_list.GetSize())
            {
                const bool show_bytes = true;
                const bool show_address = true;
                Instruction *instruction = instruction_list.GetInstructionAtIndex(0).get();

                ExecutionContext exe_ctx(thread.GetProcess());
                const char* opcode = instruction->GetMnemonic(&exe_ctx);

                if (strcmp(opcode, "jmpl") == 0)
                {
                    const char* operands_str = instruction->GetOperands(&exe_ctx);

                    // Detect trampolines with pattern jmpl *0x400800 where 0x400800 contains the DLL function pointer
                    // TODO1: Detect jmp address without string parsing (from MCInst)
                    // TODO2: We should check import table for 0x400800 instead of fetching the pointer behind it (in PECOFF)
                    unsigned long operand_ptr = strtoul(operands_str + 3, NULL, 16);
                    Error error;
                    unsigned long operand_value = process_sp->ReadPointerFromMemory(operand_ptr, error);

                    Address sc_addr;
                    if (process_sp->GetTarget().GetSectionLoadList().ResolveLoadAddress(operand_value, sc_addr))
                    {
                        SymbolContext sc;
                        thread.GetProcess()->GetTarget().GetImages().ResolveSymbolContextForAddress(sc_addr, eSymbolContextSymbol, sc);
                        if (sc.symbol != NULL)
                        {
                            thread_plan_sp.reset(new ThreadPlanRunToAddress(thread, operand_value, false));
                        }
                    }
                }
            }
        }
    }

    return thread_plan_sp;
}
