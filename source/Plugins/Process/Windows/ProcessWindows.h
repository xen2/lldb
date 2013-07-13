//===-- ProcessWindows.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_ProcessWindows_H_
#define liblldb_ProcessWindows_H_

// C Includes

// C++ Includes
#include <queue>

// Other libraries and framework includes
#include "lldb/Target/Process.h"
#include "lldb/Host/windows/windows.h"
#include "../POSIX/ProcessMessage.h"

class ProcessWindows :
    public lldb_private::Process
{
public:
    //------------------------------------------------------------------
    // Static functions.
    //------------------------------------------------------------------
    static lldb::ProcessSP
    CreateInstance(lldb_private::Target& target,
                   lldb_private::Listener &listener,
                   const lldb_private::FileSpec *);

    static void
    Initialize();

    static void
    Terminate();

    static lldb_private::ConstString
    GetPluginNameStatic();

    static const char *
    GetPluginDescriptionStatic();

    //------------------------------------------------------------------
    // Constructors and destructors
    //------------------------------------------------------------------
    ProcessWindows(lldb_private::Target& target,
                 lldb_private::Listener &listener);

    virtual
    ~ProcessWindows();

    //------------------------------------------------------------------
    // PluginInterface protocol
    //------------------------------------------------------------------
    virtual lldb_private::ConstString
    GetPluginName();

    virtual uint32_t
    GetPluginVersion();

    //------------------------------------------------------------------
    // Process protocol.
    //------------------------------------------------------------------
    virtual bool
    CanDebug(lldb_private::Target &target, bool plugin_specified_by_name);

    virtual lldb_private::Error
    WillLaunch(lldb_private::Module *module);

    virtual bool
    CheckPendingMessages();

    virtual bool
    DestroyRequiresHalt() { return false; }

    //virtual lldb_private::Error
    //DoAttachToProcessWithID(lldb::pid_t pid);

    virtual lldb_private::Error
    DoAttachToProcessWithID (lldb::pid_t pid, const lldb_private::ProcessAttachInfo &attach_info);

    virtual lldb_private::Error
    DoLaunch (lldb_private::Module *exe_module,
              lldb_private::ProcessLaunchInfo &launch_info);

    virtual void
    DidLaunch();

    virtual lldb_private::Error
    DoResume();

    virtual lldb_private::Error
    DoHalt(bool &caused_stop);

    virtual lldb_private::Error
    DoDetach(bool keep_stopped);

    virtual lldb_private::Error
    DoSignal(int signal);

    virtual lldb_private::Error
    DoDestroy();

    virtual void
    RefreshStateAfterStop();

    virtual bool
    IsAlive();

    virtual size_t
    DoReadMemory(lldb::addr_t vm_addr,
                 void *buf,
                 size_t size,
                 lldb_private::Error &error);

    virtual size_t
    DoWriteMemory(lldb::addr_t vm_addr, const void *buf, size_t size,
                  lldb_private::Error &error);

    virtual lldb::addr_t
    DoAllocateMemory(size_t size, uint32_t permissions,
                     lldb_private::Error &error);

    virtual lldb_private::Error
    DoDeallocateMemory(lldb::addr_t ptr);

    virtual lldb::addr_t
    ResolveIndirectFunction(const lldb_private::Address *address, lldb_private::Error &error);

    virtual size_t
    GetSoftwareBreakpointTrapOpcode(lldb_private::BreakpointSite* bp_site);

    virtual lldb_private::Error
    EnableBreakpointSite(lldb_private::BreakpointSite *bp_site);

    virtual lldb_private::Error
    DisableBreakpointSite(lldb_private::BreakpointSite *bp_site);

    virtual lldb_private::Error
    EnableWatchpoint(lldb_private::Watchpoint *wp, bool notify = true);

    virtual lldb_private::Error
    DisableWatchpoint(lldb_private::Watchpoint *wp, bool notify = true);

    virtual lldb_private::Error
    GetWatchpointSupportInfo(uint32_t &num);

    virtual lldb_private::Error
    GetWatchpointSupportInfo(uint32_t &num, bool &after);

    virtual uint32_t
    UpdateThreadListIfNeeded();

    virtual bool
    UpdateThreadList(lldb_private::ThreadList &old_thread_list,
                     lldb_private::ThreadList &new_thread_list);

    virtual lldb::ByteOrder
    GetByteOrder() const;

    virtual lldb::addr_t
    GetImageInfoAddress();

    virtual size_t
    PutSTDIN(const char *buf, size_t len, lldb_private::Error &error);

    static lldb::thread_result_t
    DebuggerThreadFunction (void *arg);

    void
    SendMessage(const ProcessMessage &message, bool wait_for_resume = true);

    /// Stops all threads in the process.
    /// The \p stop_tid parameter indicates the thread which initiated the stop.
    virtual void
    StopAllThreads(lldb::tid_t stop_tid);

    virtual lldb_private::DynamicLoader *
    GetDynamicLoader ();

protected:
    /// The module we are executing.
    lldb_private::Module *m_module;

    lldb_private::Mutex m_message_mutex;
    std::queue<ProcessMessage> m_message_queue;

    HANDLE m_hProcess;

    HANDLE m_resume_event;
    HANDLE m_resumed_event;

    bool m_stopping_threads;
    bool m_first_breakpoint_reached;
    bool m_expect_async_break;
};

#endif  // liblldb_MacOSXProcess_H_
