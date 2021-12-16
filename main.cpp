#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <signal.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>

typedef BOOL Error;

class Debugger
{
private:
    HANDLE hProcess = nullptr;
    DWORD pid = 0;
    BOOL active = FALSE;
    HANDLE hThread = nullptr;
    DWORD exception = 0;
    void* exception_addr = nullptr;
    CONTEXT ctx = { 0 };
    std::map<uintptr_t, uintptr_t*> software_breakpoints;
    std::map<uintptr_t, int> hardware_breakpoints;
public:

    Debugger() {

    }

    void load(std::string path_to_exe)
    {
        BOOL bCreated = FALSE;
        PROCESS_INFORMATION pinfo;
        STARTUPINFOA stinfo;
        stinfo.cb = sizeof(STARTUPINFO);
        stinfo.dwFlags = DEBUG_PROCESS;
        stinfo.wShowWindow = (WORD)CREATE_NO_WINDOW;

        bCreated = CreateProcessA(path_to_exe.c_str(),
            NULL, NULL, NULL,
            FALSE, DEBUG_PROCESS,
            NULL, NULL, &stinfo,
            &pinfo);
        if (bCreated)
        {
            puts("[*] We have successfully launched the process!");
            printf("[*] PID: %d\n", pinfo.dwProcessId);
            this->hProcess = this->open_process(pinfo.dwProcessId);
        }
        else
            printf("[*] Error: 0x%08x.\n", GetLastError());
    }

    HANDLE open_process(int pid)
    {
        HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, pid, FALSE);
        return h_process;
    }

    void attach(int pid)
    {
        this->hProcess = this->open_process(pid);
        if (DebugActiveProcess(pid))
        {
            this->active = TRUE;
            this->pid = pid;
            this->run();
        }
    }

    void run()
    {
        while (this->active)
        {
            this->get_debug_event();
        }
    }

    void get_debug_event()
    {

        DEBUG_EVENT Event;
        DWORD continue_status = DBG_CONTINUE;
        if (WaitForDebugEvent(&Event, INFINITE))
        {
            this->hThread = this->open_thread(Event.dwThreadId);
            this->ctx = this->get_thread_context(Event.dwThreadId);
            printf("[*] Event Code: %d Thread ID: %d\n", Event.dwDebugEventCode, Event.dwThreadId);
           /* ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, continue_status);*/

            if (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            {
                this->exception = Event.u.Exception.ExceptionRecord.ExceptionCode;
                this->exception_addr = Event.u.Exception.ExceptionRecord.ExceptionAddress;
                printf("[*] Exception code: %lu\n", this->exception);
            }
            if (this->exception == EXCEPTION_ACCESS_VIOLATION)
            {
                puts("[*] Access Violation Detected");
            }
            else if (this->exception == EXCEPTION_BREAKPOINT)
            {
                continue_status = this->exception_handler_breakpoint();
            }
            else if (this->exception == EXCEPTION_GUARD_PAGE)
            {
                puts("[*] Guard Page Access Detected.");
            }
            else if (this->exception == EXCEPTION_SINGLE_STEP)
            {
                this->exception_handler_single_step();
            }
                
            ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, continue_status);
        }

    }

    BOOL exception_handler_single_step()
    {
        int slot = -1;
        if (this->ctx.Dr6 & 0x1 && this->hardware_breakpoints.count(0))
            slot = 1;
    }

    DWORD exception_handler_breakpoint()
    {
        printf("[*] Inside the breakpoint handler.\n");
        printf("[*] Exception Address: 0x%16p\n",this->exception_addr);
        return DBG_CONTINUE;
    }

    BOOL detach()
    {
        if (DebugActiveProcessStop(this->pid))
        {
            puts("[*] Finished debugging. Exiting ...");
            return TRUE;
        }
        else
        {
            puts("There was an error");
            return FALSE;
        }
    }

    HANDLE open_thread(int threadId)
    {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
            THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);

        if (hThread != NULL)
        {
            return hThread;
        }
        else
        {
            puts("[*] Could not obtain a valid thread handle");
            return NULL;
        }
    }

    std::vector<DWORD> enumerate_threads()
    {
        BOOL bSuccess = TRUE;
        THREADENTRY32 entry;
        static std::vector<DWORD> thread_list;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->pid);
        puts("Got handle to snapshot object ...");
        if (hSnapshot != NULL)
        {
            puts("Snapshot not null");
            entry.dwSize = sizeof(THREADENTRY32);
            bSuccess = Thread32First(hSnapshot, &entry);
            puts("Trying to get first thread Object");
            while (bSuccess)
            {
                bSuccess = Thread32Next(hSnapshot, &entry);
                if (entry.th32OwnerProcessID == this->pid)
                {
                    printf("Owner PID: %d. ThreadId: %d\n", entry.th32OwnerProcessID, entry.th32ThreadID);
                    thread_list.push_back(entry.th32ThreadID);
                }

            }
            CloseHandle(hSnapshot);
            return thread_list;
        }
        else
        {
            thread_list.push_back((DWORD)-1);
            return thread_list;
        }

    }


    CONTEXT get_thread_context(int threadId)
    {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        HANDLE hThread = this->open_thread(threadId);
        Sleep(100);
        if (SuspendThread(hThread) == -1)
        {
            printf("Error suspending thread.. 0x%08x\n", GetLastError());
            CloseHandle(hThread);
        }
        if (GetThreadContext(hThread, &ctx))
        {
            ResumeThread(hThread);
            return ctx;
        }
        
        else
        {
            ResumeThread(hThread);
            CloseHandle(hThread);
            ctx.ContextFlags = (DWORD)-1;
            return ctx;
        }
    }

    char* read_process_memory(uintptr_t addr, size_t length)
    {
        char* buff = new char[length];
        size_t count = 0;
        if (ReadProcessMemory(this->hProcess, (void*)addr,buff,length,&count));
        {
            return buff;
        }
        delete[] buff;
        return NULL;
    }

    BOOL write_process_memory(uintptr_t addr, char* data,size_t length)
    {
        size_t count = 0;
        DWORD dwOldProtect = 0;
        BOOL bPermChanged = FALSE;
        bPermChanged = VirtualProtect((void*)addr, length, PAGE_EXECUTE_READWRITE, &dwOldProtect);

        if (bPermChanged && WriteProcessMemory(this->hProcess, (void*)addr, data, length, &count))
        {
            VirtualProtect((void*)addr, length,dwOldProtect, &dwOldProtect);
            return TRUE;
        }
        return FALSE;
    }

    BOOL bp_set(uintptr_t addr)
    {
        if (!this->software_breakpoints.count(addr))
        {
            try 
            {
                char *original_byte = this->read_process_memory(addr, 1);
                printf("original byte %s", original_byte);
                BOOL bWritten = this->write_process_memory(addr, (char*)"\xCC", 1);
                if (!bWritten)
                    throw FALSE;
                uintptr_t* info = new uintptr_t[2];
                info[0] = addr;
                info[1] = original_byte[0];
                this->software_breakpoints[addr] = info;
            }
            catch(Error e){
                return e;
            }
        }
        return TRUE;
    }



    uintptr_t func_resolve(char* dllname, char* function)
    {
        HMODULE DllHandle = LoadLibraryA(dllname);
        if (DllHandle == NULL)
        {
            puts("DllHandle is NULL");
            return NULL;
        }
        FARPROC addr = GetProcAddress(DllHandle,function);
        FreeLibrary(DllHandle);
        return (uintptr_t)addr;
    }
};

//void sighandler(int signum)
//{
//    dbg.detach();
//}

int main()
{
    //signal(SIGINT, sighandler);
    Debugger dbg;
    int pid;

    printf("Enter the PID of the process to attach to: ");
    scanf_s("%d", &pid);
    puts("Attaching to process ...");

    dbg.attach(pid);

    char dllname[] = "msvcp140";
    char function[] = "printf";
    uintptr_t addr = dbg.func_resolve(dllname,function);

    printf("Addr: %16p\n", (void*)addr);

    dbg.bp_set(addr);
    dbg.run();
}