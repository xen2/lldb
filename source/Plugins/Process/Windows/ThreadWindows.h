//===-- ThreadWindows.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_ThreadWindows_H_
#define liblldb_ThreadWindows_H_

// C Includes
// C++ Includes
#include <memory>

// Other libraries and framework includes
#include "lldb/Target/Thread.h"
#include "lldb/Host/windows/windows.h"
#include "RegisterContextPOSIX.h"
#include "../POSIX/ProcessMessage.h"

class ProcessMessage;
class ProcessMonitor;
class RegisterContextWindowsDebug_i386;

//------------------------------------------------------------------------------
// @class POSIXThread
// @brief Abstraction of a linux process (thread).
class ThreadWindows
    : public lldb_private::Thread
{
public:
    ThreadWindows(lldb_private::Process &process, HANDLE handle);

    virtual ~ThreadWindows();

    void
    RefreshStateAfterStop();

    virtual void
    WillResume(lldb::StateType resume_state);

    // This notifies the thread when a private stop occurs.
    virtual void
    DidStop ();

    const char *
    GetInfo();

    virtual lldb::RegisterContextSP
    GetRegisterContext();

    virtual lldb::RegisterContextSP
    CreateRegisterContextForFrame (lldb_private::StackFrame *frame);

    //--------------------------------------------------------------------------
    // These functions provide a mapping from the register offset
    // back to the register index or name for use in debugging or log
    // output.

    unsigned
    GetRegisterIndexFromOffset(unsigned offset);

    const char *
    GetRegisterName(unsigned reg);

    const char *
    GetRegisterNameFromOffset(unsigned offset);

    //--------------------------------------------------------------------------
    // These methods form a specialized interface to linux threads.
    //
    bool Resume();

    void Notify(const ProcessMessage &message);

    //--------------------------------------------------------------------------
    // These methods provide an interface to watchpoints
    //
    bool EnableHardwareWatchpoint(lldb_private::Watchpoint *wp);

    bool DisableHardwareWatchpoint(lldb_private::Watchpoint *wp);

    uint32_t NumSupportedHardwareWatchpoints();

    HANDLE GetHandle();

private:
    POSIXBreakpointProtocol *
    GetRegisterContextWindows ()
    {
        if (!m_reg_context_sp)
            m_reg_context_sp = GetRegisterContext();
        return m_posix_thread;
    }

    std::unique_ptr<lldb_private::StackFrame> m_frame_ap;

    lldb::BreakpointSiteSP m_breakpoint;
    ProcessMessage m_pending_message;

    POSIXBreakpointProtocol *m_posix_thread;

    HANDLE m_handle;

    virtual bool
    CalculateStopInfo();

    lldb_private::Unwind *
    GetUnwinder();

    friend class ProcessWindows;
    friend class RegisterContextWindowsDebug_i386;
};

#endif // #ifndef liblldb_POSIXThread_H_