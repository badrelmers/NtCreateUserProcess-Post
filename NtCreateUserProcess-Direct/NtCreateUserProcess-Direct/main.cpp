#include <iostream>
#include "ntapi.hpp"
#include "output.hpp"
#include "csrss.hpp"
#define ALIGN(x,align)      (((ULONG)(x)+(align)-1UL)&(~((align)-1UL)))

//#define OUTPUT
int wmain(int argc, wchar_t* argv[])
{
	LPCWSTR ImageName = NULL;
	wchar_t FallbackPath[MAX_PATH] = { 0 }; // Buffer to hold the resolved SystemDrive path

	if (argc == 1)
	{
		wprintf(L"[*] Example: NtCreateUserProcess-Post.exe C:\\Windows\\system32\\notepad.exe\n[!] On Windows 11 Notepad.exe is AppX so it doesn't work.(AppX no supported yet)\n");

		// Dynamically read %SystemDrive% (e.g., "C:")
		DWORD envResult = GetEnvironmentVariableW(L"SystemDrive", FallbackPath, MAX_PATH);
		
		if (envResult > 0 && envResult < MAX_PATH)
		{
			wcscat_s(FallbackPath, L"\\Windows\\System32\\dfrgui.exe");
			ImageName = FallbackPath;
		}
		else
		{
			// Hardcoded safety fallback if the environment variable read fails
			ImageName = L"C:\\Windows\\System32\\dfrgui.exe";
		}
		wprintf(L"[*] Run the default: %ls\n", ImageName);
	}
	else if (argc == 2)
	{
		ImageName = argv[1];
	}
	else
	{
		wprintf(L"[*] Example: NtCreateUserProcess-Post.exe C:\\Windows\\system32\\notepad.exe\n[!] On Windows 11 Notepad.exe is AppX so it doesn't work.(AppX no supported yet)\n");
		return -1;
	}
	NTSTATUS Status = 0;
	SECTION_IMAGE_INFORMATION SectionImageInfomation = { 0 };
	ULONG sizeReturn = 0;
	HANDLE ParentProcessHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID clientId = { 0 };
	CLIENT_ID ClientId = { 0 };
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	t_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = (t_RtlCreateProcessParametersEx)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");

	// Direct call through ntdll — not the syscall stub in syscalls.asm.
	// This is what a userland hook (e.g. sandboxie-style) can intercept.
	// SW3_PopulateSyscallList() is still triggered by NtOpenProcess below,
	// so CsrPortHandle / BasepConstructSxsCreateProcessMessage are still found
	// in time for CallCsrss.
	typedef NTSTATUS(NTAPI* t_NtCreateUserProcess)(
		PHANDLE              ProcessHandle,
		PHANDLE              ThreadHandle,
		ACCESS_MASK          ProcessDesiredAccess,
		ACCESS_MASK          ThreadDesiredAccess,
		POBJECT_ATTRIBUTES   ProcessObjectAttributes,
		POBJECT_ATTRIBUTES   ThreadObjectAttributes,
		ULONG                ProcessFlags,
		ULONG                ThreadFlags,
		PVOID                ProcessParameters,
		PPS_CREATE_INFO      CreateInfo,
		PPS_ATTRIBUTE_LIST   AttributeList);
	t_NtCreateUserProcess pNtCreateUserProcess =
		(t_NtCreateUserProcess)GetProcAddress(ntdll, "NtCreateUserProcess");
	if (!pNtCreateUserProcess)
	{
		wprintf(L"[-] Failed to resolve NtCreateUserProcess from ntdll\n");
		return -1;
	}
	wprintf(L"[+] ntdll!NtCreateUserProcess (direct): %p\n", pNtCreateUserProcess);
	clientId.UniqueProcess = UlongToHandle(GetCurrentProcessId());
	clientId.UniqueThread = (HANDLE)0;
	
	Status = NtOpenProcess(&ParentProcessHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
	wprintf(L"[*] NtOpenProcess: 0x%08x\n", Status);
	if (!NT_SUCCESS(Status))
		return Status;
	wprintf(L"[+] Parent process handle: %p\n", ParentProcessHandle);

	PROCESS_BASIC_INFORMATION mesInfos = { 0 };
	wprintf(L"[*] NtQueryInformationProcess: 0x%08x\n", NtQueryInformationProcess(ParentProcessHandle, ProcessBasicInformation, &mesInfos, sizeof(PROCESS_BASIC_INFORMATION), &sizeReturn));
	wprintf(L"[+] ProcessBasicInformation sizereturn %d\n", sizeReturn);
	PEB peb = { 0 };
	SIZE_T val1 = 0;
	wprintf(L"[*] PebBaseAddress NtReadVirtualMemory: 0x%08x\n", NtReadVirtualMemory(ParentProcessHandle, mesInfos.PebBaseAddress, &peb, sizeof(peb), &val1));
	wprintf(L"[+] peb readsize: %zd\n", val1);

	ACTIVATION_CONTEXT_DATA ActivationContextData = { 0 };
	wprintf(L"[*] ParentProcess Peb.ActivationContextData: 0x%p\n", peb.ActivationContextData);
	wprintf(L"[*] ParentProcess Peb.SystemDefaultActivationContextData: 0x%p\n", peb.SystemDefaultActivationContextData);

	UNICODE_STRING NtPath = { 0 };
	UNICODE_STRING Win32Path = { 0 };
	UNICODE_STRING CommandLine = { 0 };

	if (ImageName != NULL)
	{
		//Use Heap will be better?
		WCHAR NtImageName[MAX_PATH] = { 0 };
		wcscat_s(NtImageName, L"\\??\\");
		wcscat_s(NtImageName, ImageName);
		NtPath.Buffer = NtImageName;
		NtPath.Length = sizeof(WCHAR)*lstrlenW(NtImageName) ;
		NtPath.MaximumLength = sizeof(WCHAR) * lstrlenW(NtImageName)+ sizeof(UNICODE_NULL);
		
		Win32Path.Buffer = (PWSTR)ImageName;
		Win32Path.Length = sizeof(WCHAR) * lstrlenW(ImageName);
		Win32Path.MaximumLength = sizeof(WCHAR) * lstrlenW(ImageName) + sizeof(UNICODE_NULL);

		WCHAR cmdline[MAX_PATH] = { 0 };
		wcscat_s(cmdline, L"\"");// required while blankspace exist =.=
		wcscat_s(cmdline, ImageName);
		wcscat_s(cmdline, L"\"");
		CommandLine.Buffer = (PWSTR)cmdline;
		CommandLine.Length = sizeof(WCHAR) * lstrlenW(cmdline);
		CommandLine.MaximumLength = sizeof(WCHAR) * lstrlenW(cmdline) + sizeof(UNICODE_NULL);
	}
	else
	{
		exit(-1);
	}
	PS_CREATE_INFO CreateInfo = { 0 };
	RtlSecureZeroMemory(&CreateInfo, sizeof(PS_CREATE_INFO));
	CreateInfo.State = PsCreateInitialState;
	CreateInfo.Size = sizeof(PS_CREATE_INFO);
	CreateInfo.InitState.u1.InitFlags = 3;
	//CreateInfo.InitState.u1.s1.WriteOutputOnExit = TRUE;
	//CreateInfo.InitState.u1.s1.DetectManifest = TRUE;
	//CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics = IMAGE_FILE_DLL;
	CreateInfo.InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

	PRTL_USER_PROCESS_PARAMETERS OwnParameters = NtCurrentPeb()->ProcessParameters;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	//UNICODE_STRING defaultDesktop;
	//RtlInitUnicodeString(&defaultDesktop, L"Winsta0\\Default");

	if (RtlCreateProcessParametersEx == NULL)
	{
		wprintf(L"[-] RtlCreateProcessParametersEx = 0x%08x\n", RtlCreateProcessParametersEx);
		exit(-1);
	}
	Status = RtlCreateProcessParametersEx(&ProcessParameters,
		&Win32Path,
		NULL,                        // Create a new DLL path
		&OwnParameters->CurrentDirectory.DosPath,
		&CommandLine,
		NULL,                        // If null, a new environment will be created
		&Win32Path,                  // Window title is the exe path - needed for console apps
		&OwnParameters->DesktopInfo, // Copy our desktop name
		NULL,
		NULL,
		RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	wprintf(L"[*] RtlCreateProcessParametersEx: 0x%08x\n", Status);
	if (!NT_SUCCESS(Status))
		return Status;
	ULONG AttributeListCount = 4;
	SIZE_T TotalLength = AttributeListCount * sizeof(PS_ATTRIBUTE) + sizeof(SIZE_T);
	PS_ATTRIBUTE_LIST AttributeList;
	RtlSecureZeroMemory(&AttributeList, TotalLength);
	AttributeList.TotalLength = TotalLength;
	//ReturnLength no need to set in most of time
	AttributeList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
	AttributeList.Attributes[0].Size = NtPath.Length;
	AttributeList.Attributes[0].Value = (ULONG_PTR)NtPath.Buffer;

	AttributeList.Attributes[1].Attribute = PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE);
	AttributeList.Attributes[1].Size = sizeof(HANDLE);
	AttributeList.Attributes[1].ValuePtr = ParentProcessHandle;//PPID

	AttributeList.Attributes[2].Attribute = PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE);
	AttributeList.Attributes[2].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList.Attributes[2].ValuePtr = &SectionImageInfomation;

	AttributeList.Attributes[3].Attribute = PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE);
	AttributeList.Attributes[3].Size = sizeof(CLIENT_ID);
	AttributeList.Attributes[3].Value = (ULONG_PTR)&ClientId;

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	// Direct call — goes through ntdll's stub, not our syscalls.asm.
	// A userland hook on ntdll!NtCreateUserProcess will intercept this.
	Status = pNtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, 0, 1, ProcessParameters, &CreateInfo, &AttributeList);
	wprintf(L"[*] NtCreateUserProcess (direct): 0x%08x\n", Status);
	if (!NT_SUCCESS(Status))
		return Status;
	PEB peb2 = { 0 };
	ActivationContextData = { 0 };
#ifdef OUTPUT
	CreateInfoOutPut(CreateInfo);
	SectionImageInfomationOutPut(SectionImageInfomation);
#endif
	
	wprintf(L"[*] PID=%d, TID=%d\n", ClientId.UniqueProcess,ClientId.UniqueThread);
	wprintf(L"[*] CustomCallCsrss: 0x%08x\n",
	CallCsrss(hProcess, hThread, CreateInfo, Win32Path, NtPath, ClientId, SectionImageInfomation.DllCharacteristics));

	wprintf(L"[*] PEB2Address NtReadVirtualMemory: 0x%08x\n", NtReadVirtualMemory(hProcess, (PVOID)CreateInfo.SuccessState.PebAddressNative, &peb2, sizeof(peb2), &val1));
	wprintf(L"[*] peb2.SystemDefaultActivationContextData 0x%p\n", peb2.SystemDefaultActivationContextData);
	wprintf(L"[*] peb2.ActivationContextData 0x%p\n", peb2.ActivationContextData);
	wprintf(L"[*] NtResumeThread: 0x%08x\n", NtResumeThread(hThread, 0));
	return 0;
}