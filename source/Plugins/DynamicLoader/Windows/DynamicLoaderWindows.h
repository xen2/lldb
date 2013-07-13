//===-- DynamicLoaderWindows.h ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_DynamicLoaderWindows_H_
#define liblldb_DynamicLoaderWindows_H_

// C Includes
// C++ Includes
// Other libraries and framework includes
#include "lldb/Breakpoint/StoppointCallbackContext.h"
#include "lldb/Target/DynamicLoader.h"

class AuxVector;

class DynamicLoaderWindows : public lldb_private::DynamicLoader
{
public:

    static void
    Initialize();

    static void
    Terminate();

    static lldb_private::ConstString
    GetPluginNameStatic();

    static const char *
    GetPluginDescriptionStatic();

    static lldb_private::DynamicLoader *
    CreateInstance(lldb_private::Process *process, bool force);

    DynamicLoaderWindows(lldb_private::Process *process);

    virtual
    ~DynamicLoaderWindows();

    //------------------------------------------------------------------
    // DynamicLoader protocol
    //------------------------------------------------------------------

    virtual void
    DidAttach();

    virtual void
    DidLaunch();

    virtual lldb::ThreadPlanSP
    GetStepThroughTrampolinePlan(lldb_private::Thread &thread,
                                 bool stop_others);

    virtual lldb_private::Error
    CanLoadImage();

    //------------------------------------------------------------------
    // PluginInterface protocol
    //------------------------------------------------------------------
    virtual lldb_private::ConstString
    GetPluginName();

    virtual uint32_t
    GetPluginVersion();

    virtual void
    GetPluginCommandHelp(const char *command, lldb_private::Stream *strm);

    virtual lldb_private::Error
    ExecutePluginCommand(lldb_private::Args &command, lldb_private::Stream *strm);

    virtual lldb_private::Log *
    EnablePluginLogging(lldb_private::Stream *strm, lldb_private::Args &command);

protected:
    /// Virtual load address of the inferior process.
    lldb::addr_t m_load_offset;

    /// Virtual entry address of the inferior process.
    lldb::addr_t m_entry_point;

private:
    DISALLOW_COPY_AND_ASSIGN(DynamicLoaderWindows);
};

#endif  // liblldb_DynamicLoaderPOSIXDYLD_H_
