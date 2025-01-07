#include "windows.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
HANDLE hKernel; 
WCHAR KernelDev[] = L"\\\\.\\NtCreateLowboxToken";
WCHAR DriverName[] = L"NtCreateLowboxToken";
#include "winioctl.h"
BOOL LoadKernelDriver()
{
    WCHAR CurrentPath[MAX_PATH] = { 0 };
    WCHAR driverPath[MAX_PATH] = L"\\??\\";
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL success = FALSE;

    __try {

        hKernel = CreateFile(KernelDev, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

        if (hKernel != INVALID_HANDLE_VALUE)
        {
            success = TRUE;
            __leave;
        }

        // Get Windows directory and create full driver path
        if (!GetCurrentDirectoryW(MAX_PATH , (LPWSTR)CurrentPath)) {
            __leave;
        }

        PathAppend(driverPath, CurrentPath);


        PathAppend(driverPath, L"\\NtCreateLowboxToken.sys");

        // Open SCM
        hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!hSCManager) {
            __leave;
        }

        // Check if service exists
        hService = OpenService(hSCManager, DriverName, SERVICE_ALL_ACCESS);
        if (hService) {

            StartService(hService, 0, 0);

 
            hKernel = CreateFile(KernelDev, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

            if (hKernel != INVALID_HANDLE_VALUE)
            {
                success = TRUE;
            }
            __leave;

        }

        // Create service
        hService = CreateService(
            hSCManager,
            DriverName,
            DriverName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (!hService) {
            __leave;
        }

        // Start service
        if (!StartService(hService, 0, NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_SERVICE_ALREADY_RUNNING) {
                __leave;
            }
        }

        hKernel = CreateFile(KernelDev, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

        if (hKernel != INVALID_HANDLE_VALUE)
        {
            success = TRUE;
        }
    }
    __finally {
        // Cleanup
       if (hService) {
            CloseServiceHandle(hService);
        }
        if (hSCManager) {
            CloseServiceHandle(hSCManager);
        }

 
    }



    return success;

}

#include "stdio.h"

#include <dbghelp.h>
#include <psapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define SystemModuleInformation 11
PVOID GetKernelBase() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return NULL;

    ULONG size = 0;
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);

    PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(size);
    if (!moduleInfo) return NULL;

    if (NtQuerySystemInformation(SystemModuleInformation, moduleInfo, size, &size) != 0) {
        free(moduleInfo);
        return NULL;
    }   
    PVOID kernelBase = moduleInfo->Module[0].ImageBase;
    free(moduleInfo);

    return kernelBase;
}



BOOL GetKernelSymbolAddress(const char* symbolPath, const char* symbolName, DWORD64* address) {
    HANDLE process = GetCurrentProcess();
    DWORD64 baseAddr;
    char ntos[MAX_PATH];

    GetSystemDirectoryA(ntos, sizeof(ntos));
    strcat_s(ntos, sizeof(ntos), "\\ntoskrnl.exe");

    if (!SymInitialize(process, symbolPath, FALSE)) {
        printf("SymInitialize failed: %d\n", GetLastError());
        return FALSE;
    }
    baseAddr = SymLoadModule64(
        process,
        NULL,
        ntos,
        NULL,
        0, 
        0
    );

    if (!baseAddr) {
        printf("SymLoadModule64 failed: %d\n", GetLastError());
        SymCleanup(process);
        return FALSE;
    }

    SYMBOL_INFO* symbolInfo;
    symbolInfo = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    memset(symbolInfo, 0, sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo->MaxNameLen = MAX_SYM_NAME;

    if (!SymFromName(process, symbolName, symbolInfo)) {
        printf("SymFromName failed: %s %d\n",symbolName, GetLastError());
        free(symbolInfo);
        SymCleanup(process);
        return FALSE;
    }

    *address = symbolInfo->Address - baseAddr;

    free(symbolInfo);
    SymCleanup(process);
    return TRUE;
}
#include <winternl.h>

#define IOCTL_NTCREATELOWBOXTOKEN CTL_CODE(FILE_DEVICE_UNKNOWN , 0x100 , METHOD_BUFFERED , FILE_ANY_ACCESS)
#define IOCTL_GET_SYSTEM_SYMBOLS CTL_CODE(FILE_DEVICE_UNKNOWN , 0x101 , METHOD_BUFFERED , FILE_ANY_ACCESS)

typedef struct _LOWBOXTOKEN_PARAMS {
    PHANDLE             TokenHandle;          // _Out_
    HANDLE              ExistingTokenHandle;  // _In_
    ACCESS_MASK         DesiredAccess;        // _In_
    POBJECT_ATTRIBUTES  ObjectAttributes;     // _In_
    PSID                PackageSid;           // _In_
    ULONG               CapabilityCount;      // _In_
    PSID_AND_ATTRIBUTES Capabilities;         // _In_
    ULONG               HandleCount;          // _In_
    HANDLE* Handles;              // _In_
} LOWBOXTOKEN_PARAMS, * PLOWBOXTOKEN_PARAMS;
const char* symbols[] = {
    "LowboxSessionMapLock",
    "g_SessionLowboxArray",
    "g_SessionLowboxMap",
    "SepLearningModeTokenCount",
    "g_SepSidMapping",
    "SepTokenCapabilitySidSharingEnabled",
    "SepDuplicateToken"
};

PVOID KernelSymbols[sizeof(symbols) / sizeof(char*)];

typedef struct SYSTEM_SYMBOLS_PARAMS {
    PVOID LowboxSessionMapLock;
    PVOID g_SessionLowboxArray;
    PVOID g_SessionLowboxMap;
    PVOID SepLearningModeTokenCount;
    PVOID g_SepSidMapping;
    PVOID SepTokenCapabilitySidSharingEnabled;
    PVOID SepDuplicateToken;
}SYSTEM_SYMBOLS_PARAMS, * PSYSTEM_SYMBOLS_PARAMS;

BYTE g_original_bytes[16];
PVOID g_original_func;
#pragma comment(lib, "ntdll.lib")
NTSTATUS
NTSYSAPI
RtlGetLastNtStatus(
    VOID
);
typedef NTSTATUS(*PNT_CREATE_LOWBOX_TOKEN)(
    _Out_ PHANDLE             TokenHandle,
    _In_  HANDLE              ExistingTokenHandle,
    _In_  ACCESS_MASK         DesiredAccess,
    _In_  POBJECT_ATTRIBUTES  ObjectAttributes,
    _In_  PSID                PackageSid,
    _In_  ULONG               CapabilityCount,
    _In_  PSID_AND_ATTRIBUTES Capabilities,
    _In_  ULONG               HandleCount,
    _In_  HANDLE* Handles);

PNT_CREATE_LOWBOX_TOKEN NtCreateLowboxToken;

NTSTATUS NTAPI MyNtCreateLowboxToken(
    _Out_ PHANDLE             TokenHandle,
    _In_  HANDLE              ExistingTokenHandle,
    _In_  ACCESS_MASK         DesiredAccess,
    _In_  POBJECT_ATTRIBUTES  ObjectAttributes,
    _In_  PSID                PackageSid,
    _In_  ULONG               CapabilityCount,
    _In_  PSID_AND_ATTRIBUTES Capabilities,
    _In_  ULONG               HandleCount,
    _In_  HANDLE* Handles)
{
    LOWBOXTOKEN_PARAMS lowbox;

    lowbox.TokenHandle = TokenHandle; 
    lowbox.ExistingTokenHandle = ExistingTokenHandle; 
    lowbox.DesiredAccess = DesiredAccess; 
    lowbox.ObjectAttributes = ObjectAttributes; 
    lowbox.PackageSid = PackageSid; 
    lowbox.CapabilityCount = CapabilityCount; 
    lowbox.Capabilities = Capabilities; 
    lowbox.HandleCount = HandleCount; 
    lowbox.Handles = Handles; 

    DWORD btr;

    if (DeviceIoControl(hKernel, IOCTL_NTCREATELOWBOXTOKEN, &lowbox, sizeof(lowbox), NULL, 0, &btr, NULL) == FALSE)
    {
        printf("error %08x\n", *(NTSTATUS*)((ULONG_PTR)NtCurrentTeb() + 0x1250));
        return *(NTSTATUS*)((ULONG_PTR)NtCurrentTeb() + 0x1250); //teb->lastntstatusvalue
    }
    else
    {
        return 0; 
    }
}

BOOL InstallHook()
{
    BYTE jump[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, addr
        0xFF, 0xE0                                                      // jmp rax
    };

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

     g_original_func = GetProcAddress(hNtdll, "NtCreateLowBoxToken");
     if (!g_original_func)
     {
         printf("no ntclt \n");
         return FALSE; 
    }

    memcpy(g_original_bytes, g_original_func, 16);

    PVOID pBuf = VirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(pBuf, g_original_func, 0x20);
 
    NtCreateLowboxToken = (PNT_CREATE_LOWBOX_TOKEN)pBuf;
    
    *(UINT64*)(jump + 2) = (UINT64)MyNtCreateLowboxToken;

    DWORD oldProtect;
    if (!VirtualProtect(g_original_func, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        printf("vp failed %u\n ", GetLastError());

    }


       memcpy(g_original_func, jump, sizeof(jump));


    VirtualProtect(g_original_func, 16, PAGE_EXECUTE_READ, &oldProtect);

    return TRUE;
}
#include <Sddl.h>
#include <Userenv.h>
#include <AccCtrl.h>
#include <Aclapi.h>

#pragma comment(lib, "Userenv.lib")

//List of allowed capabilities for the application
extern WELL_KNOWN_SID_TYPE app_capabilities[] =
{
    WinCapabilityPrivateNetworkClientServerSid,
};

WCHAR container_name[] = L"MtSandboxTest";
WCHAR container_desc[] = L"MalwareTech Sandbox Test";


BOOL IsInAppContainer();
BOOL SetSecurityCapabilities(PSID container_sid, SECURITY_CAPABILITIES* capabilities, PDWORD num_capabilities);
BOOL GrantNamedObjectAccess(PSID appcontainer_sid, CHAR* object_name, SE_OBJECT_TYPE object_type, DWORD access_mask);

BOOL RunExecutableInContainer(CHAR* executable_path)
{
    PSID sid = NULL;
    HRESULT result;
    SECURITY_CAPABILITIES SecurityCapabilities = { 0 };
    DWORD num_capabilities = 0;
    SIZE_T attribute_size = 0;
    STARTUPINFOEXA startup_info = { 0 };
    PROCESS_INFORMATION process_info = { 0 };
    CHAR desktop_file[MAX_PATH];
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    CHAR* string_sid = NULL;
    BOOL success = FALSE;

    do //Not a loop
    {
        result = CreateAppContainerProfile(container_name, container_name, container_desc, NULL, 0, &sid);
        if (!SUCCEEDED(result))
        {
            if (HRESULT_CODE(result) == ERROR_ALREADY_EXISTS)
            {
                result = DeriveAppContainerSidFromAppContainerName(container_name, &sid);
                if (!SUCCEEDED(result))
                {
                    printf("Failed to get existing AppContainer name, error code: %d", HRESULT_CODE(result));
                    break;
                }
            }
            else {
                printf("Failed to create AppContainer, last error: %d\n", HRESULT_CODE(result));
                break;
            }
        }

        printf("[Container Info]\nname: %ws\ndescription: %ws\n", container_name, container_desc);

        if (ConvertSidToStringSidA(sid, &string_sid))
            printf("Sid: %s\n\n", string_sid);

        if (!SetSecurityCapabilities(sid, &SecurityCapabilities, &num_capabilities))
        {
            printf("Failed to set security capabilities, last error: %d\n", GetLastError());
            break;
        }

        ExpandEnvironmentStringsA("%userprofile%\\desktop\\allowed_test.txt", desktop_file, MAX_PATH - 1);

        file_handle = CreateFileA(desktop_file, GENERIC_ALL, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
        if (file_handle == INVALID_HANDLE_VALUE)
        {
            printf("Failed to create file %s, last error: %d\n", desktop_file, GetLastError());
            break;
        }

        if (!GrantNamedObjectAccess(sid, desktop_file, SE_FILE_OBJECT, FILE_ALL_ACCESS))
        {
            printf("Failed to grant explicit access to %s\n", desktop_file);
            break;
        }

        InitializeProcThreadAttributeList(NULL, 1, NULL, &attribute_size);
        startup_info.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attribute_size);

        if (!InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, NULL, &attribute_size))
        {
            printf("InitializeProcThreadAttributeList() failed, last error: %d", GetLastError());
            break;
        }

        if (!UpdateProcThreadAttribute(startup_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &SecurityCapabilities, sizeof(SecurityCapabilities), NULL, NULL))
        {
            printf("UpdateProcThreadAttribute() failed, last error: %d", GetLastError());
            break;
        }

        if (!CreateProcessA(executable_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
            (LPSTARTUPINFOA)&startup_info, &process_info))
        {
            printf("Failed to create process %s, last error: %d\n", executable_path, GetLastError());
            break;
        }

        printf("Successfully executed %s in AppContainer\n", executable_path);
        success = TRUE;

    } while (FALSE);

    if (startup_info.lpAttributeList)
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);

    if (SecurityCapabilities.Capabilities)
        free(SecurityCapabilities.Capabilities);

    if (sid)
        FreeSid(sid);

    if (string_sid)
        LocalFree(string_sid);

    if (file_handle != INVALID_HANDLE_VALUE)
        CloseHandle(file_handle);

    if (file_handle != INVALID_HANDLE_VALUE && !success)
        DeleteFileA(desktop_file);

    return success;
}
BOOL SetSecurityCapabilities(PSID container_sid, SECURITY_CAPABILITIES* capabilities, PDWORD num_capabilities)
{
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    DWORD num_capabilities_ = sizeof(app_capabilities) / sizeof(DWORD);
    SID_AND_ATTRIBUTES* attributes;
    BOOL success = TRUE;

    attributes = (SID_AND_ATTRIBUTES*)malloc(sizeof(SID_AND_ATTRIBUTES) * num_capabilities_);

    ZeroMemory(capabilities, sizeof(SECURITY_CAPABILITIES));
    ZeroMemory(attributes, sizeof(SID_AND_ATTRIBUTES) * num_capabilities_);

    for (unsigned int i = 0; i < num_capabilities_; i++)
    {
        attributes[i].Sid = malloc(SECURITY_MAX_SID_SIZE);
        if (!CreateWellKnownSid(app_capabilities[i], NULL, attributes[i].Sid, &sid_size))
        {
            success = FALSE;
            break;
        }
        attributes[i].Attributes = SE_GROUP_ENABLED;
    }

    if (success == FALSE)
    {
        for (unsigned int i = 0; i < num_capabilities_; i++)
        {
            if (attributes[i].Sid)
                LocalFree(attributes[i].Sid);
        }

        free(attributes);
        attributes = NULL;
        num_capabilities_ = 0;
    }

    capabilities->Capabilities = attributes;
    capabilities->CapabilityCount = num_capabilities_;
    capabilities->AppContainerSid = container_sid;
    *num_capabilities = num_capabilities_;

    return success;
}

/*
    Explicitly grants the container access to a named object (file, section, etc)
*/
BOOL GrantNamedObjectAccess(PSID appcontainer_sid, CHAR* object_name, SE_OBJECT_TYPE object_type, DWORD access_mask)
{
    EXPLICIT_ACCESS_A explicit_access;
    PACL original_acl = NULL, new_acl = NULL;
    DWORD status;
    BOOL success = FALSE;

    do
    {
        explicit_access.grfAccessMode = GRANT_ACCESS;
        explicit_access.grfAccessPermissions = access_mask;
        explicit_access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

        explicit_access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        explicit_access.Trustee.pMultipleTrustee = NULL;
        explicit_access.Trustee.ptstrName = (CHAR*)appcontainer_sid;
        explicit_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicit_access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
         
        status = GetNamedSecurityInfoA(object_name, object_type, DACL_SECURITY_INFORMATION, NULL, NULL, &original_acl,
            NULL, NULL);
        if (status != ERROR_SUCCESS)
        {
            printf("GetNamedSecurityInfoA() failed for %s, error: %d\n", object_name, status);
            break;
        }

        status = SetEntriesInAclA(1, &explicit_access, original_acl, &new_acl);
        if (status != ERROR_SUCCESS)
        {
            printf("SetEntriesInAclA() failed for %s, error: %d\n", object_name, status);
            break;
        }

        status = SetNamedSecurityInfoA(object_name, object_type, DACL_SECURITY_INFORMATION, NULL, NULL, new_acl, NULL);
        if (status != ERROR_SUCCESS)
        {
            printf("SetNamedSecurityInfoA() failed for %s, error: %d\n", object_name, status);
            break;
        }

        success = TRUE;

    } while (FALSE);

 /*   if (original_acl)
        LocalFree(original_acl);

    if (new_acl)
        LocalFree(new_acl);*/

    return success;
}
BOOL LoadSymbol()
{
    //replace with your symbol path
    //you'd better have the latest dbghelp.dll placed with this exe
    
    const char* symPath = "c:\\Symbols";
    DWORD64 address;
    PVOID kernelbase = GetKernelBase();
    LOWBOXTOKEN_PARAMS tp; 


    printf("Kernel Base: %p\n", kernelbase);



    for (int i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        address = 0;
        GetKernelSymbolAddress(symPath, symbols[i], &address);

        if (address == 0)
        {
            KernelSymbols[i] = 0;

            if (strcmp(symbols[i], "SepLearningModeTokenCount") == 0)
            {
                printf("SepLearningModeTokenCount not found , allowed\n");
            }
            else
            {
                printf("failed to get kernel symbol\n");
                return FALSE;
            }
        }
        else
        {
            *(ULONG_PTR*)((ULONG_PTR)&tp + sizeof(ULONG_PTR) * i ) = (ULONG_PTR)(address + (ULONG_PTR)kernelbase);
        }
        printf("%s Kernel Address: %p\n", symbols[i], *(ULONG_PTR*)((ULONG_PTR)&tp + sizeof(ULONG_PTR) * i));
    }

    DWORD btr; 

    if (DeviceIoControl(hKernel, IOCTL_GET_SYSTEM_SYMBOLS, &tp, sizeof(tp), NULL, 0, &btr, NULL) == FALSE)
    {
        printf("load system symbol failed %u\n", GetLastError());
        return FALSE;
    }

    return TRUE; 
    
}
int main()
{
    if (LoadKernelDriver() == FALSE)
    {
        printf("load driver failed %u\n", GetLastError());
        return 0;
    }

    if (LoadSymbol() == FALSE)
    {
        return 0; 
    }

    if (InstallHook() == FALSE)
    {
        return 0; 
    }




     CHAR Name[] = "c:\\windows\\system32\\notepad.exe";
    
    RunExecutableInContainer(Name);

 

}
