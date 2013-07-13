//===-- ProcessWindows.cpp ----------------------------------------*- C++ -*-===//
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
#include "lldb/Breakpoint/Watchpoint.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/State.h"
#include "lldb/Core/Log.h"
#include "lldb/Host/FileSpec.h"
#include "lldb/Host/Host.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/DynamicLoader.h"
#include "lldb/Target/Platform.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/ThreadPlan.h"

#include "ProcessWindows.h"
#include "ThreadWindows.h"

using namespace lldb;
using namespace lldb_private;

class ThreadPlanPropagatePendingMessage : public ThreadPlan
{
    ProcessMessage m_pending_message;
public:
    ThreadPlanPropagatePendingMessage(Thread &thread, ProcessMessage pending_message)
        : ThreadPlan(ThreadPlan::eKindGeneric,
            "Windows Propagate Pending Message",
            thread,
            eVoteNoOpinion,
            eVoteNoOpinion),
        m_pending_message(pending_message)
    {
    }

    bool
    ValidatePlan(Stream *error)
    {
        return true;
    }

    bool
    ShouldStop(Event *event_ptr)
    {
        SetPlanComplete();
        return true;
    }

    void
    GetDescription (Stream *s, lldb::DescriptionLevel level)
    {
        s->Printf("Propagate pending message on resume");
    }

    bool
    DoPlanExplainsStop(Event *event_ptr)
    {
        return true;
    }

    lldb::StateType
    GetPlanRunState()
    {
        return eStateRunning;
    }

    bool
    WillStop()
    {
        ProcessWindows* process = static_cast<ProcessWindows*>(m_thread.GetProcess().get());
        process->SendMessage(m_pending_message);
        return true;
    }

    bool
    DoWillResume(lldb::StateType resume_state, bool current_plan)
    {
        return false;
    }

private:
    DISALLOW_COPY_AND_ASSIGN(ThreadPlanPropagatePendingMessage);
};

//------------------------------------------------------------------------------
// Static functions.

ProcessSP
ProcessWindows::CreateInstance(Target &target, Listener &listener, const FileSpec *)
{
    return ProcessSP(new ProcessWindows(target, listener));
}

void
ProcessWindows::Initialize()
{
    static bool g_initialized = false;

    if (!g_initialized)
    {
        g_initialized = true;
        PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                      GetPluginDescriptionStatic(),
                                      CreateInstance);
    }
}

void
ProcessWindows::Terminate()
{
}

//------------------------------------------------------------------------------
// ProcessInterface protocol.

lldb_private::ConstString
ProcessWindows::GetPluginName()
{
    return GetPluginNameStatic();
}

uint32_t
ProcessWindows::GetPluginVersion()
{
    return 1;
}

lldb_private::ConstString
ProcessWindows::GetPluginNameStatic()
{
    static ConstString g_name("windows");
    return g_name;
}

const char *
ProcessWindows::GetPluginDescriptionStatic()
{
    return "Process plugin for Windows";
}

//------------------------------------------------------------------------------
// Constructors and destructors.

ProcessWindows::ProcessWindows(Target& target, Listener &listener)
    : Process(target, listener),
      m_module(NULL),
      m_message_mutex(Mutex::eMutexTypeRecursive),
      m_stopping_threads(false),
      m_first_breakpoint_reached(false),
      m_expect_async_break(false)
{
    m_resume_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    m_resumed_event = CreateEvent(NULL, FALSE, FALSE, NULL);
}

ProcessWindows::~ProcessWindows()
{
    CloseHandle(m_resume_event);
    CloseHandle(m_resumed_event);
}

//------------------------------------------------------------------------------
// Process protocol.

bool
ProcessWindows::CanDebug(Target &target, bool plugin_specified_by_name)
{
    return true;
}

Error
ProcessWindows::WillLaunch(Module* module)
{
    Error error;
    return error;
}

bool
ProcessWindows::CheckPendingMessages()
{
    Error error;

    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_PROCESS));

    // Check for pending messages.
    // Not sure if it's better to check during Process::WillResume() or right before ContinueDebugEvent().
    uint32_t thread_count = m_thread_list.GetSize(false);
    for (uint32_t i = 0; i < thread_count; ++i)
    {
        ThreadWindows *thread = static_cast<ThreadWindows*>(
            m_thread_list.GetThreadAtIndex(i, false).get());

        auto resume_state = thread->GetResumeState();
        if ((resume_state == lldb::eStateRunning || resume_state == lldb::eStateStepping)
            && thread->m_pending_message.GetKind() != ProcessMessage::eInvalidMessage)
        {
            // Some pending message was thrown previously but delayed until thread was officially "resumed"
            if (log)
                log->Printf("ThreadWindows::%s (), replaying pending event for tid = %" PRIi64, __FUNCTION__, GetID());
            ProcessMessage message = thread->m_pending_message;
            thread->m_pending_message = ProcessMessage();
            SendMessage(message, true);

            // Generate a continue & a stopped event.
            //SetPrivateState(eStateRunning);
            //SetPrivateState(eStateStopped);

            return true;
        }
    }

    return false;
}

struct LaunchArgs
{
    LaunchArgs(ProcessWindows* process,
               const std::string& executable,
               const char* working_dir,
               const std::string& command,
               Flags launchFlags)
        : process(process),
          executable(executable),
          working_dir(strdup(working_dir)),
          command(strdup(command.c_str())),
          launchFlags(launchFlags),
          pid(0)
    {

    }

    LaunchArgs(ProcessWindows* process,
               lldb::pid_t pid)
        : process(process),
          working_dir(NULL),
          command(NULL),
          pid(pid)
    {
    }

    ~LaunchArgs()
    {
        free(working_dir);
        free(command);
    }

    ProcessWindows* process;
    std::string executable;
    char* working_dir;
    char* command;
    Flags launchFlags;
    lldb::pid_t pid;
};

thread_result_t
ProcessWindows::DebuggerThreadFunction (void *arg)
{
    LaunchArgs* launchArgs = (LaunchArgs*)arg;
    ProcessWindows* process = launchArgs->process;

    DWORD dwProcessId = 0;

    // Starting the process (delayed until here because debugging loop need to be in the same thread)
    if (launchArgs->pid != 0)
    {
        process->m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, launchArgs->pid);
        dwProcessId = GetProcessId(process->m_hProcess);
        DebugActiveProcess(dwProcessId);
        DebugSetProcessKillOnExit(false);
    }
    else
    {
        PROCESS_INFORMATION process_information;
        STARTUPINFO startupInfo;
        memset(&startupInfo, 0, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);
        bool processCreated = CreateProcessA(launchArgs->executable.c_str(), launchArgs->command, NULL, NULL, false, DEBUG_ONLY_THIS_PROCESS, NULL, launchArgs->working_dir, &startupInfo, &process_information);
        process->m_hProcess = process_information.hProcess;
        dwProcessId = process_information.dwProcessId;
    }

    process->SetID((user_id_t)dwProcessId);

    bool bFirstException = true;

    DEBUG_EVENT debug_event = {0};
    DWORD dwContinueStatus = DBG_CONTINUE;
    bool bProcessRunning = true;

    // Main debugger loop
    // Need to happen on the thread starting the process
    while (bProcessRunning)
    {
        // Wait for next debug event
        if (!WaitForDebugEvent(&debug_event, INFINITE))
            return -1;

        switch(debug_event.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            {
                // Update load address of main module
                ModuleSP module = process->GetTarget().GetExecutableModule();
                bool loadAddrChanged;
                module->SetLoadAddress(process->GetTarget(), (addr_t) debug_event.u.CreateProcessInfo.lpBaseOfImage, false, loadAddrChanged);

                // Add main thread
                if (debug_event.u.CreateProcessInfo.hThread != NULL)
                {
                    ThreadSP thread_sp;
                    thread_sp.reset(new ThreadWindows(*process, debug_event.u.CreateProcessInfo.hThread));

                    process->m_thread_list.AddThread(thread_sp);
                }

                CloseHandle(debug_event.u.CreateProcessInfo.hFile);

                //process->SetPublicState(lldb::eStateStopped);
            }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            {
                int suspendCount = SuspendThread(debug_event.u.CreateThread.hThread);
                process->SendMessage(ProcessMessage::NewThread((tid_t) debug_event.dwThreadId, (tid_t) debug_event.u.CreateThread.hThread));
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            process->SendMessage(ProcessMessage::Exit((tid_t)debug_event.dwThreadId, debug_event.u.ExitThread.dwExitCode));
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            bProcessRunning = false;
            break;
        case EXCEPTION_DEBUG_EVENT:
            switch(debug_event.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_BREAKPOINT:
                // Ignore first chance exceptions
                //if (debug_event.u.Exception.dwFirstChance == 0 || bFirstException)
                {
                    bFirstException = false;
                    process->SendMessage(ProcessMessage::Break((tid_t)debug_event.dwThreadId));
                }
                break;
            case EXCEPTION_SINGLE_STEP:
                process->SendMessage(ProcessMessage::Trace((tid_t)debug_event.dwThreadId));
                break;
            }
            break;
        case LOAD_DLL_DEBUG_EVENT:
            {
                char pathBuffer[MAX_PATH];
                GetFinalPathNameByHandle(debug_event.u.LoadDll.hFile, pathBuffer, MAX_PATH, VOLUME_NAME_DOS);
                CloseHandle(debug_event.u.LoadDll.hFile);

                char* path = pathBuffer;
                // Not sure why URL starts with \\?\, so let's skip it.
                if (strncmp(path, "\\\\?\\", 4) == 0)
                    path += 4;

                FileSpec file_spec(path, false);
                ModuleSpec module_spec(file_spec);
                ModuleSP module = process->GetTarget().GetSharedModule(module_spec);
                bool loadAddrChanged;
                module->SetLoadAddress(process->GetTarget(), (addr_t)debug_event.u.LoadDll.lpBaseOfDll, false, loadAddrChanged);
            }
            break;
        }

        // Process messages
        while (process->CheckPendingMessages())
        {
        }

        // Continue execution
        ContinueDebugEvent(debug_event.dwProcessId,
            debug_event.dwThreadId,
            dwContinueStatus);
    }

    return 0;
}

void
ProcessWindows::StopAllThreads(lldb::tid_t stop_tid)
{
    // If a breakpoint occurs while we're stopping threads, we'll get back
    // here, but we don't want to do it again.  Only the MonitorChildProcess
    // thread calls this function, so we don't need to protect this flag.
    if (m_stopping_threads)
        return;
    m_stopping_threads = true;

    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log)
        log->Printf ("ProcessWindows::%s() stopping all threads", __FUNCTION__);

    // Walk the thread list and stop the other threads.  The thread that caused
    // the stop should already be marked as stopped before we get here.
    Mutex::Locker thread_list_lock(m_thread_list.GetMutex());

    uint32_t thread_count = m_thread_list.GetSize(false);
    for (uint32_t i = 0; i < thread_count; ++i)
    {
        ThreadWindows *thread = static_cast<ThreadWindows*>(
            m_thread_list.GetThreadAtIndex(i, false).get());
        assert(thread);
        lldb::tid_t tid = thread->GetID();
        if (!StateIsStoppedState(thread->GetState(), false))
            SuspendThread(thread->GetHandle());
    }

    m_stopping_threads = false;

    if (log)
        log->Printf ("ProcessLinux::%s() finished", __FUNCTION__);
}

void
ProcessWindows::SendMessage(const ProcessMessage &message, bool wait_for_resume)
{
    Mutex::Locker lock(m_message_mutex);

    ThreadWindows *thread = static_cast<ThreadWindows*>(
        m_thread_list.FindThreadByID(message.GetTID(), false).get());

    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log)
        log->Printf("ThreadWindows::%s () tid = %" PRIi64 " Processing message %" PRIi32, __FUNCTION__, message.GetTID(), (uint32_t)message.GetKind());

    // Process and dispatch messages
    switch (message.GetKind())
    {
    case ProcessMessage::eInvalidMessage:
        return;

    case ProcessMessage::eExitMessage:
        if (thread)
            thread->SetState(eStateExited);
        break;
    case ProcessMessage::eTraceMessage:
    case ProcessMessage::eBreakpointMessage:
    case ProcessMessage::eNewThreadMessage:
    case ProcessMessage::eCrashMessage:
        if (message.GetKind() == ProcessMessage::eBreakpointMessage && thread != NULL)
        {
            // In case of known breakpoint, instruction has already been executed so we need to go back one byte,
            // so that it can later be replaced with real code through ThreadPlanStepOverBreakpoint.

            // Get PC
            lldb::addr_t pc = thread->GetRegisterContext()->GetPC();

            if (log)
                log->Printf("ThreadWindows::%s () tid = %" PRIi64 " Breakpoint at PC=0x%8.8" PRIx64, __FUNCTION__, thread->GetID(), pc);

            if (thread->GetResumeState() == eStateSuspended
                || thread->GetTemporaryResumeState() == eStateSuspended)
            {
                // Thread is suspended so we delay this event propagation until thread is resumed.
                // This happens when two threads A and B reach a breakpoint, thread A is processed first and asked to step over (with thread B suspended).
                // Still thread B will throw the breakpoint event right after ContinueDebugEvent is called, event if it has been suspended.
                thread->m_pending_message = message;
                //ThreadPlanSP thread_plan_sp;
                //thread_plan_sp.reset(new ThreadPlanPropagatePendingMessage(*thread, message));
                //thread->QueueThreadPlan(thread_plan_sp, false);

                if (log)
                    log->Printf("ThreadWindows::%s () Added pending breakpoint for tid = %" PRIi64 " at PC = 0x%8.8" PRIx64, __FUNCTION__, thread->GetID(), pc);

                return;
            }
        }

        // If currently in a DebugBreakProcess sequence, ignore NewThreadMessage otherwise Process::Halt will interpret the thread creation as the actual stop.
        // Another way would be to wait in a loop until we reach an unexpected breakpoint.
        if (m_expect_async_break && message.GetKind() == ProcessMessage::eNewThreadMessage)
        {
            m_message_queue.push(message);
            ResumeThread((HANDLE)message.GetChildTID());
            m_expect_async_break = false;
            return;
        }

        if (thread)
            thread->SetState(eStateStopped);

        // Stop all threads
        StopAllThreads(message.GetTID());

        {
            // Send stopped message
            lldb::StateType private_state = GetPrivateState();
            SetPrivateState(eStateStopped);
            m_message_queue.push(message);
            lock.Unlock();


            // Wait until we are told to resume
            if (wait_for_resume)
                WaitForSingleObject(m_resume_event, INFINITE);
        }
        return;
    default:
        return;
    }

    m_message_queue.push(message);
}

Error
ProcessWindows::DoAttachToProcessWithID(lldb::pid_t pid, const lldb_private::ProcessAttachInfo &attach_info)
{
    Error error;

    LaunchArgs* launchArgs = new LaunchArgs(this, pid);

    // Start debugger thread
    Host::ThreadCreate("debugger",
        DebuggerThreadFunction,
        launchArgs,
        NULL);

    // Initial state is stopped
    SetPublicState(eStateStopped, false);

    return error;
}

Error
ProcessWindows::DoLaunch (Module *module,
                       ProcessLaunchInfo &launch_info)
{
    Error error;

    SetPrivateState(eStateLaunching);

    const char* working_dir = launch_info.GetWorkingDirectory();

    std::string command;
    if (!launch_info.GetArguments().GetCommandString(command))
        return error;

    LaunchArgs* launchArgs = new LaunchArgs(this, launch_info.GetExecutableFile().GetPath(), working_dir, command, launch_info.GetFlags());

    // Start debugger thread
    Host::ThreadCreate("debugger",
                        DebuggerThreadFunction,
                        launchArgs,
                        NULL);

    // Initial state is stopped
    SetPublicState(eStateStopped, false);

    return error;
}

void
ProcessWindows::DidLaunch()
{
}

Error
ProcessWindows::DoResume()
{
    Error error;

    StateType state = GetPrivateState();

    assert(state == eStateStopped || state == eStateCrashed);

    // Update private state
    if (state == eStateStopped)
    {
        SetPrivateState(eStateRunning);
    }

    // Resume threads
    bool did_resume = false;
    uint32_t thread_count = m_thread_list.GetSize(false);
    for (uint32_t i = 0; i < thread_count; ++i)
    {
        ThreadWindows *thread = static_cast<ThreadWindows*>(
            m_thread_list.GetThreadAtIndex(i, false).get());
        did_resume = thread->Resume() || did_resume;
    }
    assert(did_resume && "Process resume failed!");

    // Notify debugger loop to continue
    SetEvent(m_resume_event);

    return error;
}

addr_t
ProcessWindows::GetImageInfoAddress()
{
    Target *target = &GetTarget();
    ObjectFile *obj_file = target->GetExecutableModule()->GetObjectFile();
    Address addr = obj_file->GetImageInfoAddress(target);

    if (addr.IsValid())
        return addr.GetLoadAddress(target);
    else
        return LLDB_INVALID_ADDRESS;
}

Error
ProcessWindows::DoHalt(bool &caused_stop)
{
    Error error;

    StateType state = GetPrivateState();

    if (state == eStateStopped)
    {
        caused_stop = false;
    }
    else
    {
        m_expect_async_break = true;

        caused_stop = DebugBreakProcess(m_hProcess);
        if (!caused_stop)
            return error;

        assert(caused_stop && "Process halt failed!");
    }
    return error;
}

Error
ProcessWindows::DoDetach(bool keep_stopped)
{
    Error error;
    return error;
}

Error
ProcessWindows::DoSignal(int signal)
{
    Error error;
    return error;
}

Error
ProcessWindows::DoDestroy()
{
    Error error;

    if (GetPrivateState() != eStateDetached && GetPrivateState() == eStateExited)
    {
        if (::TerminateProcess(m_hProcess, 0) != S_OK)
        {
            error.SetErrorToErrno();
            return error;
        }

        SetPrivateState(eStateExited);
    }

    return error;
}

void
ProcessWindows::RefreshStateAfterStop()
{
    Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log && log->GetMask().Test(LIBLLDB_LOG_VERBOSE))
        log->Printf ("ProcessWindows::%s(), message_queue size = %d", __FUNCTION__, (int)m_message_queue.size());

    Mutex::Locker lock(m_message_mutex);

    while (!m_message_queue.empty())
    {
        ProcessMessage &message = m_message_queue.front();

        lldb::tid_t tid = message.GetTID();

        ThreadWindows *thread = static_cast<ThreadWindows*>(
            GetThreadList().FindThreadByID(tid, false).get());

        if (message.GetKind() == ProcessMessage::eNewThreadMessage)
        {
            if (log)
                log->Printf ("ProcessWindows::%s() adding thread, tid = %" PRIi64, __FUNCTION__, message.GetChildTID());
            ThreadSP thread_sp;
            HANDLE hThread = (HANDLE)message.GetChildTID();
            thread_sp.reset(thread = new ThreadWindows(*this, hThread));
            m_thread_list.AddThread(thread_sp);
        }

        m_thread_list.RefreshStateAfterStop();

        // Restore all threads to the real breakpoint location (if there is a breakpoint site)
        uint32_t thread_count = m_thread_list.GetSize(false);
        for (uint32_t i = 0; i < thread_count; ++i)
        {
            ThreadWindows *thread = static_cast<ThreadWindows*>(
                m_thread_list.GetThreadAtIndex(i, false).get());

            // Read context
            lldb::addr_t pc = thread->GetRegisterContext()->GetPC();

            // Adjust PC to where breakpoint was
            pc--;

            BreakpointSiteSP bp_site_sp = GetBreakpointSiteList().FindByAddress(pc);
            if (bp_site_sp)
            {
                if (log)
                    log->Printf("ThreadWindows::%s () Assigning breakpoint for tid = %" PRIi64 " to PC = 0x%8.8" PRIx64, __FUNCTION__, thread->GetID(), pc);

                thread->m_breakpoint = bp_site_sp;
            }
        }

        if (thread)
            thread->Notify(message);

        if (message.GetKind() == ProcessMessage::eExitMessage)
        {
            // FIXME: We should tell the user about this, but the limbo message is probably better for that.
            if (log)
                log->Printf ("ProcessWindows::%s() removing thread, tid = %" PRIi64, __FUNCTION__, tid);
            ThreadSP thread_sp = m_thread_list.RemoveThreadByID(tid, false);
            thread_sp->SetState(eStateExited);
            thread_sp.reset();
        }


        m_message_queue.pop();
    }
}

bool
ProcessWindows::IsAlive()
{
    StateType state = GetPrivateState();
    return state != eStateDetached
        && state != eStateExited
        && state != eStateInvalid
        && state != eStateUnloaded;
}

size_t
ProcessWindows::DoReadMemory(addr_t vm_addr,
                           void *buf, size_t size, Error &error)
{
    SIZE_T numberOfBytesRead;
    ReadProcessMemory(m_hProcess, (void*) vm_addr, buf, size, &numberOfBytesRead);
    return numberOfBytesRead;
}

size_t
ProcessWindows::DoWriteMemory(addr_t vm_addr, const void *buf, size_t size,
                            Error &error)
{
    SIZE_T numberOfBytesWritten;
    WriteProcessMemory(m_hProcess, (void*) vm_addr, buf, size, &numberOfBytesWritten);
    FlushInstructionCache(m_hProcess, (void*) vm_addr, size);
    return numberOfBytesWritten;
}

addr_t
ProcessWindows::DoAllocateMemory(size_t size, uint32_t permissions,
                               Error &error)
{
    DWORD prot;
    bool readable = (permissions & lldb::ePermissionsReadable);
    bool writable = (permissions & lldb::ePermissionsWritable);
    bool executable = (permissions & lldb::ePermissionsExecutable);

    // Compute memory protection flags
    if (readable)
    {
        if (executable)
        {
            prot = writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else
        {
            prot = writable ? PAGE_READWRITE : PAGE_READONLY;
        }
    }
    else
    {
        assert(!writable);
        prot = executable ? PAGE_EXECUTE : PAGE_NOACCESS;
    }

    // Allocate
    return (addr_t)VirtualAllocEx(m_hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, prot);
}

Error
ProcessWindows::DoDeallocateMemory(lldb::addr_t addr)
{
    Error error;

    // Deallocate
    VirtualFreeEx(m_hProcess, (LPVOID) addr, 0, MEM_RELEASE);
    return error;
}

addr_t
ProcessWindows::ResolveIndirectFunction(const Address *address, Error &error)
{
    addr_t function_addr = LLDB_INVALID_ADDRESS;
    return function_addr;
}

size_t
ProcessWindows::GetSoftwareBreakpointTrapOpcode(BreakpointSite* bp_site)
{
    static const uint8_t g_i386_opcode[] = { 0xCC };

    ArchSpec arch = GetTarget().GetArchitecture();
    const uint8_t *opcode = NULL;
    size_t opcode_size = 0;

    switch (arch.GetMachine())
    {
    default:
        assert(false && "CPU type not supported!");
        break;

    case llvm::Triple::x86:
    case llvm::Triple::x86_64:
        opcode = g_i386_opcode;
        opcode_size = sizeof(g_i386_opcode);
        break;
    }

    bp_site->SetTrapOpcode(opcode, opcode_size);
    return opcode_size;
}

Error
ProcessWindows::EnableBreakpointSite(BreakpointSite *bp_site)
{
    return EnableSoftwareBreakpoint(bp_site);
}

Error
ProcessWindows::DisableBreakpointSite(BreakpointSite *bp_site)
{
    return DisableSoftwareBreakpoint(bp_site);
}

Error
ProcessWindows::EnableWatchpoint(Watchpoint *wp, bool notify)
{
    Error error;
    return error;
}

Error
ProcessWindows::DisableWatchpoint(Watchpoint *wp, bool notify)
{
    Error error;
    return error;
}

Error
ProcessWindows::GetWatchpointSupportInfo(uint32_t &num)
{
    Error error;
    return error;
}

Error
ProcessWindows::GetWatchpointSupportInfo(uint32_t &num, bool &after)
{
    Error error = GetWatchpointSupportInfo(num);
    // Watchpoints trigger and halt the inferior after
    // the corresponding instruction has been executed.
    after = true;
    return error;
}

uint32_t
ProcessWindows::UpdateThreadListIfNeeded()
{
    // Do not allow recursive updates.
    return m_thread_list.GetSize(false);
}

bool
ProcessWindows::UpdateThreadList(ThreadList &old_thread_list, ThreadList &new_thread_list)
{
    new_thread_list = old_thread_list;
    return new_thread_list.GetSize(false) > 0;
}

ByteOrder
ProcessWindows::GetByteOrder() const
{
    // FIXME: We should be able to extract this value directly.  See comment in
    // ProcessWindows().
    return eByteOrderLittle;
}

size_t
ProcessWindows::PutSTDIN(const char *buf, size_t len, Error &error)
{
    return 0;
}

lldb_private::DynamicLoader *
ProcessWindows::GetDynamicLoader ()
{
    if (m_dyld_ap.get() == NULL)
        m_dyld_ap.reset (DynamicLoader::FindPlugin(this, NULL));
    return m_dyld_ap.get();
}
