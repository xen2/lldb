//===-- ThreadWindows.cpp -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/lldb-python.h"

// C Includes
#include <errno.h>
#include <inttypes.h>

// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Breakpoint/Watchpoint.h"
#include "lldb/Breakpoint/BreakpointSite.h"
#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/State.h"
#include "lldb/Host/Host.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/StopInfo.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/ThreadSpec.h"
#include "ThreadWindows.h"
#include "ProcessWindows.h"
#include "RegisterContextWindows_i386.h"
#include "RegisterContextWindowsDebug_i386.h"

#include "UnwindLLDB.h"

using namespace lldb;
using namespace lldb_private;

class WindowsStopInfo
    : public lldb_private::StopInfo
{
public:
    WindowsStopInfo(lldb_private::Thread &thread, uint32_t status, lldb::StopReason stop_reason)
        : StopInfo(thread, status), m_stop_reason(stop_reason)
    { }

    lldb::StopReason
    GetStopReason() const
    {
        return m_stop_reason;
    }
private:
    lldb::StopReason m_stop_reason;
};

ThreadWindows::ThreadWindows(Process &process, HANDLE handle)
    : Thread(process, GetThreadId(handle)),
      m_frame_ap(),
      m_handle(handle),
      m_posix_thread(NULL)
{
    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log && log->GetMask().Test(LIBLLDB_LOG_VERBOSE))
        log->Printf ("ThreadWindows::%s (tid = %" PRIi64 ")", __FUNCTION__, GetID());
}

ThreadWindows::~ThreadWindows()
{
    DestroyThread();
}

void
ThreadWindows::RefreshStateAfterStop()
{
    // Invalidate all registers in our register context. We don't set "force" to
    // true because the stop reply packet might have had some register values
    // that were expedited and these will already be copied into the register
    // context by the time this function gets called. The KDPRegisterContext
    // class has been made smart enough to detect when it needs to invalidate
    // which registers are valid by putting hooks in the register read and
    // register supply functions where they check the process stop ID and do
    // the right thing.
    //if (StateIsStoppedState(GetState())
    {
        const bool force = false;
        GetRegisterContext()->InvalidateIfNeeded (force);
    }
    // FIXME: This should probably happen somewhere else.
    SetResumeState(eStateRunning);
    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log)
        log->Printf ("ThreadWindows::%s (tid = %" PRIi64 ") setting thread resume state to running", __FUNCTION__, GetID());
}

const char *
ThreadWindows::GetInfo()
{
    return NULL;
}

lldb::RegisterContextSP
ThreadWindows::GetRegisterContext()
{
    if (!m_reg_context_sp)
    {
        m_posix_thread = NULL;

        ArchSpec arch = Host::GetArchitecture();

        switch (arch.GetMachine())
        {
        default:
            assert(false && "CPU type not supported!");
            break;

        case llvm::Triple::x86:
            {
                RegisterInfoInterface *reg_interface = new RegisterContextWindows_i386(arch);
                RegisterContextWindowsDebug_i386 *reg_ctx = new RegisterContextWindowsDebug_i386(*this, 0, reg_interface);
                m_posix_thread = reg_ctx;
                m_reg_context_sp.reset(reg_ctx);
                break;
            }

        case llvm::Triple::x86_64:
// TODO: Use target OS/architecture detection rather than ifdefs so that
// lldb built on FreeBSD can debug on Linux and vice-versa.
#ifdef __linux__
            m_reg_context_sp.reset(new RegisterContextLinux_x86_64(*this, 0));
#endif
#ifdef __FreeBSD__
            m_reg_context_sp.reset(new RegisterContextFreeBSD_x86_64(*this, 0));
#endif
            break;
        }
    }
    return m_reg_context_sp;
}

lldb::RegisterContextSP
ThreadWindows::CreateRegisterContextForFrame(lldb_private::StackFrame *frame)
{
    lldb::RegisterContextSP reg_ctx_sp;
    uint32_t concrete_frame_idx = 0;

    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log && log->GetMask().Test(LIBLLDB_LOG_VERBOSE))
        log->Printf ("ThreadWindows::%s ()", __FUNCTION__);

    if (frame)
        concrete_frame_idx = frame->GetConcreteFrameIndex();

    if (concrete_frame_idx == 0)
        reg_ctx_sp = GetRegisterContext();
    else
    {
        assert(GetUnwinder());
        reg_ctx_sp = GetUnwinder()->CreateRegisterContextForFrame(frame);
    }

    return reg_ctx_sp;
}

bool
ThreadWindows::CalculateStopInfo()
{
    SetStopInfo (m_stop_info_sp);
    return true;
}

Unwind *
ThreadWindows::GetUnwinder()
{
    if (m_unwinder_ap.get() == NULL)
        m_unwinder_ap.reset(new UnwindLLDB(*this));

    return m_unwinder_ap.get();
}

void
ThreadWindows::WillResume(lldb::StateType resume_state)
{
    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log)
        log->Printf ("ThreadWindows::%s (tid = %" PRIi64 ") setting thread resume state to %s", __FUNCTION__, GetID(), StateAsCString(resume_state));
    // TODO: the line below shouldn't really be done, but
    // the ThreadWindows might rely on this so I will leave this in for now
    SetResumeState(resume_state);
}

void
ThreadWindows::DidStop()
{
    // Don't set the thread state to stopped unless we really stopped.
}

bool
ThreadWindows::Resume()
{
    Mutex::Locker locker(m_state_mutex);

    lldb::StateType resume_state = GetResumeState();
    lldb::StateType current_state = GetState();
    bool status;

    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log)
        log->Printf("ThreadWindows::%s (), tid = %" PRIi64 " resume_state = %s", __FUNCTION__, GetID(),
                         StateAsCString(resume_state));

    switch (resume_state)
    {
    default:
        assert(false && "Unexpected state for resume!");
        status = false;
        break;

    case lldb::eStateRunning:
        {
            SetState(resume_state);
            int resumeCount;
            do
            {
                resumeCount = ResumeThread(GetHandle());
            } while (resumeCount > 1);
            status = resumeCount != -1;
        }
        break;

    case lldb::eStateStepping:
        {
            SuspendThread(GetHandle());

            // Set stepping flag
            SetState(resume_state);
            CONTEXT context;
            context.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(GetHandle(), &context);
            context.EFlags |= 0x100;
            SetThreadContext(GetHandle(), &context);

            // Resume this thread
            int resumeCount;
            do
            {
                resumeCount = ResumeThread(GetHandle());
            } while (resumeCount > 1);
            status = resumeCount != -1;

            //EventSP exit_event_sp;
            //StateType state = m_process_wp.lock()->WaitForProcessToStop(NULL, &exit_event_sp);
        }
        break;
    case lldb::eStateStopped:
    case lldb::eStateSuspended:
        if (current_state != lldb::eStateStopped && current_state != lldb::eStateSuspended)
            SuspendThread(GetHandle());
        status = true;
        break;
    }

    return status;
}

void
ThreadWindows::Notify(const ProcessMessage &message)
{
    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    //if (log)
    //    log->Printf ("ThreadWindows::%s () message kind = '%s'", __FUNCTION__, message.PrintKind());

    switch (message.GetKind())
    {
    default:
        assert(false && "Unexpected message kind!");
        break;

    case ProcessMessage::eExitMessage:
        // Nothing to be done.
        break;

    case ProcessMessage::eBreakpointMessage:
        {
            bool status;

            assert(GetRegisterContext());
            status = GetRegisterContextWindows()->UpdateAfterBreakpoint();
            assert(status && "Breakpoint update failed!");

            // With our register state restored, resolve the breakpoint object
            // corresponding to our current PC.
            lldb::addr_t pc = GetRegisterContext()->GetPC();
            lldb::BreakpointSiteSP bp_site(GetProcess()->GetBreakpointSiteList().FindByAddress(pc));

            if (!bp_site && m_breakpoint && m_breakpoint->GetLoadAddress() == pc)
            {
                bp_site = m_breakpoint;
                m_breakpoint.reset();
            }

            if (log)
                log->Printf("ThreadWindows::%s  (tid = %" PRIi64 ") PC=0x%8.8" PRIx64 " breakpoint site %" PRIi32, __FUNCTION__, GetID(), pc, bp_site ? bp_site->GetID() : 0);

            // If the breakpoint is for this thread, then we'll report the hit, but if it is for another thread,
            // we create a stop reason with should_stop=false.  If there is no breakpoint location, then report
            // an invalid stop reason. We don't need to worry about stepping over the breakpoint here, that will
            // be taken care of when the thread resumes and notices that there's a breakpoint under the pc.
            if (bp_site)
            {
                lldb::break_id_t bp_id = bp_site->GetID();
                if (bp_site->ValidForThisThread(this))
                    SetStopInfo(StopInfo::CreateStopReasonWithBreakpointSiteID(*this, bp_id));
                else
                {
                    const bool should_stop = false;
                    SetStopInfo(StopInfo::CreateStopReasonWithBreakpointSiteID(*this, bp_id, should_stop));
                }
            }
            else
                SetStopInfo(StopInfoSP());
        }
        break;

    case ProcessMessage::eTraceMessage:
        SetStopInfo(StopInfoSP(new WindowsStopInfo(*this, LLDB_INVALID_UID, eStopReasonTrace)));
        break;

    case ProcessMessage::eNewThreadMessage:
        SetStopInfo(StopInfoSP(new WindowsStopInfo(*this, 0, eStopReasonNone)));
        break;
    }
}

bool
ThreadWindows::EnableHardwareWatchpoint(Watchpoint *wp)
{
    return false;
}

bool
ThreadWindows::DisableHardwareWatchpoint(Watchpoint *wp)
{
    return false;
}

uint32_t
ThreadWindows::NumSupportedHardwareWatchpoints()
{
    return 0;
}

unsigned
ThreadWindows::GetRegisterIndexFromOffset(unsigned offset)
{
    unsigned reg;
    ArchSpec arch = Host::GetArchitecture();

    switch (arch.GetMachine())
    {
    default:
        assert(false && "CPU type not supported!");
        break;

    case llvm::Triple::x86:
    case llvm::Triple::x86_64:
        {
            RegisterContextSP base = GetRegisterContext();
            if (base) {
                POSIXBreakpointProtocol* reg_ctx = GetRegisterContextWindows();
                reg = reg_ctx->GetRegisterIndexFromOffset(offset);
            }
        }
        break;
    }
    return reg;
}

const char *
ThreadWindows::GetRegisterName(unsigned reg)
{
    const char * name = nullptr;
    ArchSpec arch = Host::GetArchitecture();

    switch (arch.GetMachine())
    {
    default:
        assert(false && "CPU type not supported!");
        break;

    case llvm::Triple::x86:
    case llvm::Triple::x86_64:
        name = GetRegisterContext()->GetRegisterName(reg);
        break;
    }
    return name;
}

const char *
ThreadWindows::GetRegisterNameFromOffset(unsigned offset)
{
    return GetRegisterName(GetRegisterIndexFromOffset(offset));
}

HANDLE
ThreadWindows::GetHandle()
{
    return m_handle;
}