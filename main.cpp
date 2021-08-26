#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <TlHelp32.h>
#include <signal.h>

#define MAX_THREADS 1000

bool signal_triggered = false;

STARTUPINFOA startupinfo;
PROCESS_INFORMATION processInfo;
using namespace std;

void handler(int signum)
{
	if (signum == SIGSEGV)
	{
		signal_triggered = true;
	}
}


class Debugger 
{
public:
	HANDLE h_process =  NULL;
	DWORD pid = 0;
	bool debugger_active = false;
	size_t count = 0;
	Debugger()
	{
		
	}

	void load(const char* path_to_exe)
	{
		DWORD creation_flags = DEBUG_PROCESS;
		startupinfo.dwFlags = 0x1;
		startupinfo.wShowWindow = 0x0;

		startupinfo.cb = sizeof(startupinfo);

		if(CreateProcessA(path_to_exe, NULL, NULL, NULL,NULL,creation_flags,NULL,NULL,&startupinfo,&processInfo))
		{
			puts("[*] We have successfully launched the process!");
			printf("[*] PID: %d", processInfo.dwProcessId);
			this->h_process = this->open_process(processInfo.dwProcessId);
		}
		else {
			printf("[*] Error: %x", GetLastError());
		}
	}

	HANDLE open_process(DWORD pid)
	{
		h_process = OpenProcess(PROCESS_ALL_ACCESS, pid, false);
		return h_process;
	}

	void attach(DWORD pid)
	{
		h_process = this->open_process(pid);
		if (DebugActiveProcess(pid))
		{
			this->debugger_active = true;
			this->pid = int(pid);
			this->run();
		}
		else {
			puts("[*] Unable to attach process.");
		}
	}

	void run()
	{
		while (this->debugger_active == true)
		{
			this->get_debug_event();
		}
	}

	void get_debug_event()
	{
		DEBUG_EVENT debug_event;
		DWORD continue_status = DBG_CONTINUE;
		if (WaitForDebugEvent(&debug_event, INFINITE))
		{
			/*printf("Press a key to continue...");
			this->debugger_active = false;*/
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);
		}
	}

	bool detach()
	{
		if (DebugActiveProcessStop(this->pid))
		{
			puts("[*] Finished debugging. Exiting...");
			return true;
		}
		else {
			puts("[*] There was an error");
			return false;
		}
	}

	HANDLE open_thread(DWORD thread_id)
	{
		HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, NULL, thread_id);
		if (h_thread != NULL)
		{
			return h_thread;
		}
		else {
			puts("[*] Could not obtain a valid thread handle");
			return NULL;
		}
	}

	LPDWORD enumerate_threads()
	{
		this->count = 0;
		THREADENTRY32 thread_entry;
		static DWORD thread_list[MAX_THREADS];
		//memset(thread_list, -1, MAX_THREADS);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->pid);
		if (snapshot != NULL)
		{
			thread_entry.dwSize = sizeof(thread_entry);
			bool success = Thread32First(snapshot, &thread_entry);
			while (success)
			{
				if (thread_entry.th32OwnerProcessID == this->pid)
				{
					if (this->count <= MAX_THREADS)
					{
						thread_list[this->count++] = thread_entry.th32ThreadID;
						success = Thread32Next(snapshot, &thread_entry);
					}
				}
				else {
					return NULL;
				}
			}
		}
		CloseHandle(snapshot);
		return thread_list;
	}

	LPCONTEXT get_thread_context(DWORD thread_id)
	{
		LPCONTEXT context = (LPCONTEXT)malloc(sizeof(LPCONTEXT));
		context->ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		HANDLE h_thread = this->open_thread(thread_id);
		if (GetThreadContext(h_thread, context))
		{
			CloseHandle(h_thread);
			return context;
		}
		else {
			return NULL;
		}
	}
};

int main()
{
	/*typedef void (*sigpointer)(int);
	sigpointer sighandle;
	sighandle = signal(SIGSEGV, handler);*/

	Debugger debugger;
	DWORD pid;
	LPCONTEXT thread_context;

	printf("Enter the PID of the process to attach to: ");
	scanf_s("%u", &pid);

	debugger.attach(debugger.pid);
	LPDWORD thread_list = debugger.enumerate_threads();

	for (size_t i = 0; i < debugger.count; i++)
	{
		thread_context = debugger.get_thread_context(thread_list[i]);
		printf("[*] Dumping registers for thread ID: 0x%x", thread_list[i]);
		printf("[**] rip: %llu", thread_context->Rip);
		printf("[**] rsp: %llu", thread_context->Rsp);
		printf("[**] rbp: %llu", thread_context->Rbp);
		printf("[**] rax: %llu", thread_context->Rax);
		printf("[**] rbx: %llu", thread_context->Rbx);
		printf("[**] rcx: %llu", thread_context->Rcx);
		printf("[**] rdx: %llu", thread_context->Rdx);
		printf("[*] END DUMP");
	}
	debugger.detach();
}