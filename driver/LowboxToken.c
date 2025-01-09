//MJ0011@CyberKunlun 2024.12

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "LowboxToken.h"
#pragma comment(lib, "ntoskrnl.lib")

SYSTEM_SYMBOLS_PARAMS KernelSymbols;
BOOLEAN bSystemSymbolInitialized = FALSE; 

PSID SeAppSiloSid = NULL;
PSID SeAliasAdminsSid = NULL;
PSID SePrincipalSelfSid = NULL;
PSID SeOwnerRightsSid = NULL;
PSID SeLearningModeLoggingCapabilitySid = NULL;
PSID SePermissiveLearningModeCapabilitySid = NULL;

PSID SeLpacAppExperienceCapabilitySid = NULL;
PSID SeLpacComCapabilitySid = NULL;
PSID SeLpacCryptoServicesCapabilitySid = NULL;
PSID SeLpacIdentityServicesCapabilitySid = NULL;
PSID SeLpacInstrumentationCapabilitySid = NULL;
PSID SeLpacEnterprisePolicyChangeNotificationsCapabilitySid = NULL;
PSID SeLpacMediaCapabilitySid = NULL;
PSID SeLpacPnpNotificationsCapabilitySid = NULL;
PSID SeRegistryReadCapabilitySid = NULL;
PSID SeLpacServicesManagementCapabilitySid = NULL;
PSID SeLpacSessionManagementCapabilitySid = NULL;
PSID SeLpacPrintingCapabilitySid = NULL;
PSID SeLpacWebPlatformCapabilitySid = NULL;
PSID SeLpacPaymentsCapabilitySid = NULL;
PSID SeLpacClipboardCapabilitySid = NULL;
PSID SeLpacImeCapabilitySid = NULL;
PSID SeLpacPackageManagerOperationCapabilitySid = NULL;
PSID SeLpacDeviceAccessCapabilitySid = NULL;

const PSID* SeLpacCapabilitySids[] = {
    &SeLpacAppExperienceCapabilitySid,
    &SeLpacComCapabilitySid,
    &SeLpacCryptoServicesCapabilitySid,
    &SeLpacIdentityServicesCapabilitySid,
    &SeLpacInstrumentationCapabilitySid,
    &SeLpacEnterprisePolicyChangeNotificationsCapabilitySid,
    &SeLpacMediaCapabilitySid,
    &SeLpacPnpNotificationsCapabilitySid,
    &SeRegistryReadCapabilitySid,
    &SeLpacServicesManagementCapabilitySid,
    &SeLpacSessionManagementCapabilitySid,
    &SeLpacPrintingCapabilitySid,
    &SeLpacWebPlatformCapabilitySid,
    &SeLpacPaymentsCapabilitySid,
    &SeLpacClipboardCapabilitySid,
    &SeLpacImeCapabilitySid,
    &SeLpacPackageManagerOperationCapabilitySid,
    &SeLpacDeviceAccessCapabilitySid
};

#define SE_LPAC_CAPABILITY_COUNT (sizeof(SeLpacCapabilitySids) / sizeof(PSID*))

NTSTATUS NTSYSAPI RtlSidHashInitialize(
     PSID_AND_ATTRIBUTES SidAttr,
     ULONG SidCount,
     PSID_AND_ATTRIBUTES_HASH SidAttrHash
);
NTSTATUS NTSYSAPI RtlQueryInformationAcl(
    IN PACL Acl,
    OUT PVOID AclInformation,
    IN ULONG AclInformationLength,
    IN ACL_INFORMATION_CLASS AclInformationClass
);
ULONG NTSYSAPI RtlGetCurrentServiceSessionId();

POBJECT_TYPE NTSYSAPI ObGetObjectType(PVOID Object);

POBJECT_HEADER_NAME_INFO NTSYSAPI ObQueryNameInfo(PVOID Object);

PSID_AND_ATTRIBUTES
NTSYSAPI
RtlSidHashLookup(
    _In_ PSID_AND_ATTRIBUTES_HASH SidAttrHash,
    _In_ PSID Sid);


POBJECT_TYPE ObpSymbolicLinkObjectType; 
POBJECT_TYPE ObpDirectoryObjectType;


NTSTATUS SeCaptureSid(
    __in PSID InputSid,
    __in KPROCESSOR_MODE RequestorMode,
    __inout_bcount_opt(CaptureBufferLength) PVOID CaptureBuffer,
    __in ULONG CaptureBufferLength,
    __in POOL_TYPE PoolType,
    __in BOOLEAN ForceCapture,
    __deref_out PSID* CapturedSid
)

{

    ULONG GetSidSubAuthorityCount;
    ULONG SidSize;
    
    UNREFERENCED_PARAMETER(CaptureBuffer);
    UNREFERENCED_PARAMETER(CaptureBufferLength);
    UNREFERENCED_PARAMETER(PoolType);

    if ((RequestorMode == KernelMode) && (ForceCapture == FALSE))
    {
        (*CapturedSid) = InputSid;

        return STATUS_SUCCESS;
    }

    if (RequestorMode != KernelMode)
    {

        try
        {
            GetSidSubAuthorityCount = ProbeAndReadUchar(&(((SID*)(InputSid))->SubAuthorityCount));

            SidSize = RtlLengthRequiredSid(GetSidSubAuthorityCount);

            ProbeForRead(InputSid, SidSize, sizeof(ULONG));

        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }

    }
    else 
    {

        GetSidSubAuthorityCount = ((SID*)(InputSid))->SubAuthorityCount;
        SidSize = RtlLengthRequiredSid(GetSidSubAuthorityCount);
    }

    *CapturedSid = (PSID)ExAllocatePoolWithTag((POOL_TYPE)(PagedPool | POOL_ZERO_ALLOCATION) , SidSize, SEP_SID_TAG);

    if (*CapturedSid == NULL) 
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    try
    {
        RtlCopyMemory((*CapturedSid), InputSid, SidSize);
        ((SID*)(*CapturedSid))->SubAuthorityCount = (UCHAR)GetSidSubAuthorityCount;

    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        ExFreePool(*CapturedSid);
        *CapturedSid = NULL;

        return GetExceptionCode();
    }

    if ((!RtlValidSid((*CapturedSid))))
    {
        ExFreePool((*CapturedSid));
        *CapturedSid = NULL;

        return STATUS_INVALID_SID;
    }

    return STATUS_SUCCESS;

}

SID_IDENTIFIER_AUTHORITY RtlpAppPackageAuthority = { 0 , 0 , 0 , 0 , 0 , 0xF };

//Determines the type of AppContainer SID.

/*Parameters
    AppContainerSid - the SID to classify.
    AppContainerSidType - a pointer to a variable that receives the appcontainer SID type.
*/

NTSTATUS NTAPI RtlGetAppContainerSidType(
    _In_ PISID AppContainerSid,
    _Out_ PAPPCONTAINER_SID_TYPE AppContainerSidType
)
{
    UCHAR SubAuthorityCount;

    if (AppContainerSid->SubAuthorityCount >= SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT &&
        AppContainerSid->Revision == SID_REVISION &&
        RtlCompareMemory(&AppContainerSid->IdentifierAuthority, &RtlpAppPackageAuthority, sizeof(SID_IDENTIFIER_AUTHORITY)) == sizeof(SID_IDENTIFIER_AUTHORITY) &&
        AppContainerSid->SubAuthority[0] == SECURITY_APP_PACKAGE_BASE_RID)
    {
        SubAuthorityCount = *RtlSubAuthorityCountSid(AppContainerSid);
        if (SubAuthorityCount == SECURITY_APP_PACKAGE_RID_COUNT)
        {
            *AppContainerSidType = ParentAppContainerSidType;
            return STATUS_SUCCESS;
        }
        if (SubAuthorityCount == SECURITY_CHILD_PACKAGE_RID_COUNT)
        {
            *AppContainerSidType = ChildAppContainerSidType;
            return STATUS_SUCCESS;
        }
        *AppContainerSidType = InvalidAppContainerSidType;
    }
    else
    {
        *AppContainerSidType = NotAppContainerSidType;
    }
    return STATUS_NOT_APPCONTAINER;
}

//Determines if two SIDs represent a pair of related child and parent AppContainer SIDs.

// Parameters
//    ParentAppContainerSid - a parent AppContainer SID.
//    ChildAppContainerSid - a child AppContainer SID.

BOOLEAN NTAPI RtlIsParentOfChildAppContainer(
    _In_ PSID ParentAppContainerSid,
    _In_ PSID ChildAppContainerSid

)
{
    ULONG i;
    APPCONTAINER_SID_TYPE SidType = 0 ;

    if (NT_SUCCESS(RtlGetAppContainerSidType(ParentAppContainerSid, &SidType)) &&
        SidType == ParentAppContainerSidType &&
        NT_SUCCESS(RtlGetAppContainerSidType(ChildAppContainerSid, &SidType)) &&
        SidType == ChildAppContainerSidType)
    {
        i = 1;

        for (i = 1; i < SECURITY_APP_PACKAGE_RID_COUNT; i++)
        {
            if (*RtlSubAuthoritySid(ParentAppContainerSid, i) != *RtlSubAuthoritySid(ChildAppContainerSid, i))
            {
                return FALSE; 
            }
        }

        return TRUE; 
    }
    return FALSE;
}

/*
 * Check if current process has permission to create a Low Box token
 * Returns STATUS_SUCCESS if authorized, STATUS_ACCESS_DENIED otherwise
 */

NTSTATUS SepCheckCreateLowBox(PSID CapturedSid)
{
    PTOKEN ClientToken;
    SECURITY_SUBJECT_CONTEXT SubjectContext = { 0 };

    // Capture security context
    SeCaptureSubjectContext(&SubjectContext);

    // Determine which token to use and verify impersonation level
    if (SubjectContext.ClientToken)
    {
        ClientToken = (PTOKEN)SubjectContext.ClientToken;
        if (SubjectContext.ImpersonationLevel < SecurityImpersonation)
        {
            SeReleaseSubjectContext(&SubjectContext);
            return STATUS_ACCESS_DENIED; 
        }
    }
    else
    {
        ClientToken = (PTOKEN)SubjectContext.PrimaryToken;
    }

    // Check if token has elevated privileges
    if (ClientToken->TokenFlags & TOKEN_NOT_LOW)
    {
        SeReleaseSubjectContext(&SubjectContext);
        return STATUS_SUCCESS;
    }
    // Perform deep container validation if needed
    else if ((ClientToken->TokenFlags & TOKEN_LOWBOX) &&
        RtlIsParentOfChildAppContainer(
            (PISID)ClientToken->Package,
            CapturedSid
        ))
    {
        SeReleaseSubjectContext(&SubjectContext);
        return STATUS_SUCCESS;
    }
    else
    {
        SeReleaseSubjectContext(&SubjectContext);
        return STATUS_ACCESS_DENIED;
    }
}


NTSTATUS __declspec(noalias) SeCaptureSidAndAttributesArray(
    __in_ecount(ArrayCount) PSID_AND_ATTRIBUTES InputArray,
    __in ULONG ArrayCount,
    __in KPROCESSOR_MODE RequestorMode,
    __in_bcount_opt(CaptureBufferLength) PVOID CaptureBuffer,
    __in ULONG CaptureBufferLength,
    __in POOL_TYPE PoolType, //unused
    __in BOOLEAN ForceCapture,//unused 
    __deref_out_bcount_full(*AlignedArraySize) PSID_AND_ATTRIBUTES* CapturedArray,
    __out PULONG AlignedArraySize
)
{

    typedef struct _TEMP_ARRAY_ELEMENT {
        PISID  Sid;
        ULONG SidLength;
    } TEMP_ARRAY_ELEMENT;

  


    TEMP_ARRAY_ELEMENT* TempArray = NULL;

    NTSTATUS CompletionStatus = STATUS_SUCCESS;

    ULONG ArraySize;
    ULONG AlignedLengthRequired;

    ULONG NextIndex;

    PSID_AND_ATTRIBUTES NextElement;
    PVOID NextBufferLocation;

    ULONG GetSidSubAuthorityCount;
    ULONG SidSize;
    ULONG AlignedSidSize;

    UNREFERENCED_PARAMETER(ForceCapture);
    UNREFERENCED_PARAMETER(PoolType);

    if (ArrayCount == 0)
    {
        *CapturedArray = NULL;
        *AlignedArraySize = 0;
        return STATUS_SUCCESS;
    }

    if (ArrayCount > SEP_MAX_GROUP_COUNT)
    {
        return STATUS_INVALID_PARAMETER;
    }


    ArraySize = ArrayCount * (ULONG)sizeof(TEMP_ARRAY_ELEMENT);
    AlignedLengthRequired = (ULONG)LongAlignSize(ArraySize);

    if (RequestorMode != KernelMode)
    {

        TempArray = (TEMP_ARRAY_ELEMENT*)ExAllocatePoolWithTag((POOL_TYPE)(POOL_ZERO_ALLOCATION | PagedPool), AlignedLengthRequired, 'aTeS');

        if (TempArray == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }


        try
        {

            ProbeForRead(InputArray, ArraySize, sizeof(ULONG));

            NextIndex = 0;

            while (NextIndex < ArrayCount)
            {
                PSID TempSid;

                TempSid = InputArray[NextIndex].Sid;
                GetSidSubAuthorityCount = ProbeAndReadUchar(&((PISID)TempSid)->SubAuthorityCount);

                if (GetSidSubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
                {
                    CompletionStatus = STATUS_INVALID_SID;
                    break;
                }

                TempArray[NextIndex].Sid = ((PISID)(TempSid));
                TempArray[NextIndex].SidLength = RtlLengthRequiredSid(GetSidSubAuthorityCount);

                ProbeForRead(TempArray[NextIndex].Sid, TempArray[NextIndex].SidLength, sizeof(ULONG));

                AlignedLengthRequired += (ULONG)LongAlignSize(TempArray[NextIndex].SidLength);

                NextIndex += 1;

            }

        } except(EXCEPTION_EXECUTE_HANDLER) {

            ExFreePool(TempArray);
            return GetExceptionCode();
        }

        if (!NT_SUCCESS(CompletionStatus))
        {
            ExFreePool(TempArray);
            return CompletionStatus;
        }

    }
    else
    {
        NextIndex = 0;

        while (NextIndex < ArrayCount) {

            GetSidSubAuthorityCount = ((PISID)(InputArray[NextIndex].Sid))->SubAuthorityCount;

            AlignedLengthRequired += (ULONG)LongAlignSize(RtlLengthRequiredSid(GetSidSubAuthorityCount));

            NextIndex += 1;

        }

    }

    *AlignedArraySize = AlignedLengthRequired;

    if (ARGUMENT_PRESENT(CaptureBuffer)) {

        if (AlignedLengthRequired > CaptureBufferLength) {

            if (RequestorMode != KernelMode)
            {
                ExFreePool(TempArray);
            }

            return STATUS_BUFFER_TOO_SMALL;

        }
        else {

            *CapturedArray = CaptureBuffer;
        }

    }
    else
    {
        *CapturedArray = (PSID_AND_ATTRIBUTES)ExAllocatePoolWithTag((POOL_TYPE)(POOL_ZERO_ALLOCATION | PagedPool), AlignedLengthRequired, SEP_SID_AND_ATTRIBUTES_TAG);

        if (*CapturedArray == NULL)
        {
            if (RequestorMode != KernelMode)
            {
                ExFreePool(TempArray);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (RequestorMode != KernelMode)
    {
        try
        {
            NextBufferLocation = (*CapturedArray);
            RtlCopyMemory(NextBufferLocation, InputArray, ArraySize);
            NextBufferLocation = (PVOID)((ULONG_PTR)NextBufferLocation + (ULONG)LongAlignSize(ArraySize));

            NextIndex = 0;
            NextElement = (*CapturedArray);
            while ((NextIndex < ArrayCount) && (CompletionStatus == STATUS_SUCCESS))
            {
                RtlCopyMemory(NextBufferLocation, TempArray[NextIndex].Sid, TempArray[NextIndex].SidLength);


                NextElement[NextIndex].Sid = (PSID)NextBufferLocation;

                NextBufferLocation = (PVOID)((ULONG_PTR)NextBufferLocation + (ULONG)LongAlignSize(TempArray[NextIndex].SidLength));

                if (NextElement[NextIndex].Attributes & ~(SE_GROUP_VALID_ATTRIBUTES)) {
                    CompletionStatus = STATUS_INVALID_PARAMETER;
                }
                else if (!RtlValidSid(NextElement[NextIndex].Sid)) {
                    CompletionStatus = STATUS_INVALID_SID;
                }
                else if (RtlLengthSid(NextElement[NextIndex].Sid) != TempArray[NextIndex].SidLength) {
                    CompletionStatus = STATUS_INVALID_SID;
                }

                NextIndex += 1;

            }


        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            if (!ARGUMENT_PRESENT(CaptureBuffer)) {
                ExFreePool((*CapturedArray));
                *CapturedArray = NULL;
            }

            ExFreePool(TempArray);

            return GetExceptionCode();
        }
    }
    else
    {

        NextBufferLocation = (*CapturedArray);

        RtlCopyMemory(NextBufferLocation, InputArray, ArraySize);

        NextBufferLocation = (PVOID)((ULONG_PTR)NextBufferLocation + (ULONG)LongAlignSize(ArraySize));

        NextIndex = 0;
        NextElement = (*CapturedArray);
        while (NextIndex < ArrayCount)
        {
            GetSidSubAuthorityCount = ((PISID)(NextElement[NextIndex].Sid))->SubAuthorityCount;

            SidSize = RtlLengthRequiredSid(GetSidSubAuthorityCount);

            RtlCopyMemory(NextBufferLocation, NextElement[NextIndex].Sid, SidSize);

            AlignedSidSize = (ULONG)LongAlignSize(SidSize);

            NextElement[NextIndex].Sid = (PSID)NextBufferLocation;

            NextIndex += 1;

            NextBufferLocation = (PVOID)((ULONG_PTR)NextBufferLocation + AlignedSidSize);

        }

    }

    if (RequestorMode != KernelMode)
    {
        ExFreePool(TempArray);
    }

    if (!ARGUMENT_PRESENT(CaptureBuffer) && !NT_SUCCESS(CompletionStatus))
    {

        ExFreePool(*CapturedArray);

        *CapturedArray = NULL;
    }

    return CompletionStatus;
}

VOID SeReleaseLuidAndAttributesArray(PSID_AND_ATTRIBUTES Array, KPROCESSOR_MODE Mode , BOOLEAN bForceCapture)
{
    if (((Mode == KernelMode) && (bForceCapture == TRUE)) ||
        (Mode == UserMode))
    {
        if (Array != NULL)
        {
            ExFreePool(Array);
        }
    }
}

VOID SeReleaseSid(__in PSID CapturedSid, __in KPROCESSOR_MODE RequestorMode, __in BOOLEAN ForceCapture)
{

    if (((RequestorMode == KernelMode) && (ForceCapture == TRUE)) || (RequestorMode == UserMode)) {

        ExFreePool(CapturedSid);
    }

    return;

}

NTSTATUS SepCaptureHandles(ULONG HandleCount, HANDLE* InputHandles, PHANDLE* CapturedHandles)
{
    HANDLE* AllocatedHandles;
    ULONG i;


    *CapturedHandles = NULL;

    if (HandleCount > 10)
        return STATUS_INVALID_PARAMETER_1;

    if (HandleCount == 0)
        return STATUS_SUCCESS;

    AllocatedHandles = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(HANDLE) * HandleCount, SEP_HANDLES_CAPTURE_TAG);

    if (AllocatedHandles == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try
    {
        for (i = 0; i < HandleCount; i++)
        {
            AllocatedHandles[i] = InputHandles[i];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        NTSTATUS Status;
        Status = GetExceptionCode();

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(AllocatedHandles);
        }

        return Status;
    }
    *CapturedHandles = AllocatedHandles;
    return STATUS_SUCCESS;
}

BOOLEAN RtlIsPackageSid(PISID Sid)
{
    return (Sid->SubAuthorityCount >= SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT &&
        Sid->Revision == SID_REVISION &&
        RtlCompareMemory(&Sid->IdentifierAuthority, &RtlpAppPackageAuthority, sizeof(SID_IDENTIFIER_AUTHORITY)) == sizeof(SID_IDENTIFIER_AUTHORITY) &&
        Sid->SubAuthority[0] == SECURITY_APP_PACKAGE_BASE_RID);
}

BOOLEAN RtlIsCapabilitySid(PISID Sid)
{
    return (Sid->SubAuthorityCount >= SECURITY_BUILTIN_CAPABILITY_RID_COUNT &&
        Sid->Revision == SID_REVISION &&
        RtlCompareMemory(&Sid->IdentifierAuthority, &RtlpAppPackageAuthority, sizeof(SID_IDENTIFIER_AUTHORITY)) == sizeof(SID_IDENTIFIER_AUTHORITY) &&
        Sid->SubAuthority[0] == SECURITY_CAPABILITY_BASE_RID);
}


BOOLEAN SepIsLpacCapabilitySid(PSID Sid)
{
    ULONG Index;

    for (Index = 0; Index < SE_LPAC_CAPABILITY_COUNT; Index++)
    {
        if (RtlEqualSid(Sid, *SeLpacCapabilitySids[Index]))
        {
            return TRUE;
        }
    }

    return FALSE;
}


NTSTATUS SepCheckCapabilities(PACCESS_TOKEN Token, ULONG CapabilityCount, SID_AND_ATTRIBUTES* CapabilityArray, PVOID Unused, BOOLEAN* pbCapLegit)
{
    NTSTATUS Status;
    ULONG TokenIsLPAC = 0;
    TOKEN_GROUPS* TokenGroups = NULL;
    ULONG IsAppContainer = 0;
    ULONG Index = 0;
    ULONG GroupsIndex = 0;
    PTOKEN_APPCONTAINER_INFORMATION pTokenAppcontainerSid = NULL;
    
    UNREFERENCED_PARAMETER(Unused);


    *pbCapLegit = FALSE;

    // Non-AppContainer tokens are always considered legitimate

    Status = SeQueryInformationToken(Token, TokenIsAppContainer, (PVOID) & IsAppContainer);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (IsAppContainer == 0)
    {
        *pbCapLegit = TRUE;
        goto Exit;
    }

    Status = SeQueryInformationToken(Token, TokenCapabilities, (PVOID)&TokenGroups);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = SeQueryInformationToken(Token, TokenIsLessPrivilegedAppContainer, (PVOID)&TokenIsLPAC);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    for (Index = 0; Index < CapabilityCount; Index++)
    {
        //If exisiting token is not LPAC and capability sid is lpac capability sid 

        if (TokenIsLPAC == FALSE && SepIsLpacCapabilitySid(CapabilityArray[Index].Sid))
        {
            continue;
        }

        //Already exist capability of existing token

        for (GroupsIndex = 0; GroupsIndex < TokenGroups->GroupCount; GroupsIndex++)
        {
            if (RtlEqualSid(TokenGroups->Groups[GroupsIndex].Sid, CapabilityArray[Index].Sid) &&
                TokenGroups->Groups[GroupsIndex].Attributes == CapabilityArray[Index].Attributes)
            {
                break;
            }
        }

        if (GroupsIndex != TokenGroups->GroupCount)
        {
            continue;
        }

        //not existing capability, check installer group 

        if (((PISID)CapabilityArray[Index].Sid)->SubAuthorityCount != SECURITY_INSTALLER_GROUP_CAPABILITY_RID_COUNT ||
            *(RtlSubAuthoritySid(CapabilityArray[Index].Sid, 0)) != SECURITY_CAPABILITY_BASE_RID)
        {
            *pbCapLegit = FALSE;
            break;
        }

        if (pTokenAppcontainerSid == NULL)
        {
            Status = SeQueryInformationToken(Token, TokenAppContainerSid, &pTokenAppcontainerSid);

            if (!NT_SUCCESS(Status))
            {
                break;
            }
        }

        if (*RtlSubAuthorityCountSid(pTokenAppcontainerSid->TokenAppContainer) >= SECURITY_APP_PACKAGE_RID_COUNT &&
            RtlCompareMemory(RtlSubAuthoritySid(pTokenAppcontainerSid->TokenAppContainer, 1),
                RtlSubAuthoritySid(CapabilityArray[Index].Sid, 1),
                (SECURITY_APP_PACKAGE_RID_COUNT - 1) * sizeof(ULONG)) == (SECURITY_APP_PACKAGE_RID_COUNT - 1) * sizeof(ULONG))
        {
            continue;
        }
        else
        {
            *pbCapLegit = FALSE;
            break;
        }
    }

    if (CapabilityCount == Index)
    {
        *pbCapLegit = TRUE;
    }

Exit:
    if (TokenGroups)
        ExFreePool(TokenGroups);
    if (pTokenAppcontainerSid)
        ExFreePool(pTokenAppcontainerSid);
    return Status;
}

NTSTATUS
SepDuplicateToken(
    __in PTOKEN ExistingToken,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in BOOLEAN EffectiveOnly,
    __in TOKEN_TYPE TokenType,
    __in SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    __in KPROCESSOR_MODE RequestorMode,
    __in BOOLEAN SkipNonInheritableSecurityAttributes,
    __deref_out PTOKEN* DuplicateToken
)
{
    return KernelSymbols.SepDuplicateToken(ExistingToken, ObjectAttributes, EffectiveOnly, TokenType, ImpersonationLevel, RequestorMode, SkipNonInheritableSecurityAttributes, DuplicateToken);
}

NTSTATUS SeSetMandatoryPolicyToken(PTOKEN Token, PTOKEN_MANDATORY_POLICY MandatoryPolicy)
{
    if (MandatoryPolicy->Policy & (~TOKEN_MANDATORY_POLICY_VALID_MASK))
    {
        return STATUS_INVALID_PARAMETER;
    }

    SepAcquireTokenWriteLock(Token);

    Token->MandatoryPolicy = MandatoryPolicy->Policy;

    SepReleaseTokenWriteLock(Token, TRUE);
    return STATUS_SUCCESS;
}

PSID_AND_ATTRIBUTES  SepLocateTokenIntegrity(PTOKEN Token)
{
    if (Token->IntegrityLevelIndex == -1)
    {
        return NULL;
    }

    return &Token->UserAndGroups[Token->IntegrityLevelIndex];
}
//BOOLEAN SepTokenCapabilitySidSharingEnabled;


NTSTATUS SepLengthSidAndAttributesArray(PSID_AND_ATTRIBUTES Caps, ULONG CapCount, PULONG pCapturedSize)
{
    PVOID CaptureBuffer;
    NTSTATUS Status;
    PSID_AND_ATTRIBUTES CapturedCaps;
    ULONG CapturedSize;


    CapturedSize = 0;
    CapturedCaps = NULL;

    CaptureBuffer = ExAllocatePool2(POOL_FLAG_PAGED, 8, 'aSeS');

    if (CaptureBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = SeCaptureSidAndAttributesArray(
        Caps,
        CapCount,
        KernelMode,
        CaptureBuffer,
        8,
        PagedPool,
        FALSE,
        &CapturedCaps,
        &CapturedSize);

    *pCapturedSize = CapturedSize;
    if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        Status = STATUS_SUCCESS;
    }

    ExFreePool(CaptureBuffer);
    return Status;
}
typedef struct SID_MAPPING
{
    EX_PUSH_LOCK Lock;
    PRTL_DYNAMIC_HASH_TABLE HashTable;
}SID_MAPPING, * PSID_MAPPING;

//PSID_MAPPING g_SepSidMapping;

typedef struct SHARED_SID_ENTRY {
    RTL_DYNAMIC_HASH_TABLE_ENTRY Entry;
    LONG64 ReferCount;
    PSID Sid;
}SHARED_SID_ENTRY, * PSHARED_SID_ENTRY;

PSHARED_SID_ENTRY SepFindSharedSidEntry(PISID Sid)
{
    ULONG_PTR IDAuthValue;
    PRTL_DYNAMIC_HASH_TABLE_ENTRY i;
    RTL_DYNAMIC_HASH_TABLE_CONTEXT Context;
    PSID_MAPPING g_SepSidMapping = *(PSID_MAPPING*)(KernelSymbols.g_SepSidMapping);

    memset(&Context, 0, sizeof(Context));

    IDAuthValue = SID_HASH_ULONG(Sid);

    if (IDAuthValue == 0)
    {
        IDAuthValue = 1; 
    }

    for (i = RtlLookupEntryHashTable(g_SepSidMapping->HashTable, IDAuthValue, &Context);
        ;
        i = RtlGetNextEntryHashTable(g_SepSidMapping->HashTable, &Context))
    {
        if (!i)
            break;
        if (RtlEqualSid(Sid, CONTAINING_RECORD(i, SHARED_SID_ENTRY, Entry)->Sid))
            return NULL;
    }
    return CONTAINING_RECORD(i, SHARED_SID_ENTRY, Entry);
}

VOID SepDeReferenceSharedSidEntries(PSID_AND_ATTRIBUTES Capabilities, ULONG CapabilityCount)
{
    ULONG CapCount;
    PSHARED_SID_ENTRY HashEntry;
    PSID_MAPPING g_SepSidMapping = *(PSID_MAPPING*)(KernelSymbols.g_SepSidMapping);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_SepSidMapping->Lock);

    for (CapCount = 0; CapCount < CapabilityCount; CapCount++)
    {
        HashEntry = SepFindSharedSidEntry(Capabilities[CapCount].Sid);

        PSHARED_SID_ENTRY SidEntry = CONTAINING_RECORD(HashEntry, SHARED_SID_ENTRY, Entry);
        LONG64 NewRef = InterlockedDecrement64(&SidEntry->ReferCount);

        if (NewRef <= 0)
        {
            if (NewRef)
            {
                RtlFailFast(FAST_FAIL_INVALID_REFERENCE_COUNT);
                //never return
            }

            if (RtlRemoveEntryHashTable(g_SepSidMapping->HashTable, &HashEntry->Entry, NULL))
            {
                ExFreePool(HashEntry);
            }
        }
    }

    ExReleasePushLockExclusive(&g_SepSidMapping->Lock);

    KeLeaveCriticalRegion();

    return;
}


VOID SepFreeTokenCapabilities(PTOKEN Token)
{
    if (*(BOOLEAN*)(KernelSymbols.SepTokenCapabilitySidSharingEnabled))
    {
        SepDeReferenceSharedSidEntries(Token->Capabilities, Token->CapabilityCount);
    }
    ExFreePool(Token->Capabilities);
}

NTSTATUS SepInsertOrReferenceSharedSidEntries(SID_AND_ATTRIBUTES* Capabilities , SID_AND_ATTRIBUTES* OutputSaA , ULONG CapabilityCount)
{
    NTSTATUS Status = STATUS_SUCCESS; 
    ULONG i; 
    PSHARED_SID_ENTRY SidEntry; 
    PISID Sid; 
    ULONG Signature; 
    ULONG SidEntrySize; 
    LONGLONG RefCount; 
    PSID_MAPPING g_SepSidMapping = *(PSID_MAPPING*)(KernelSymbols.g_SepSidMapping);
    
    KeEnterCriticalRegion();

    ExAcquirePushLockExclusive(&g_SepSidMapping->Lock);
    
    for (i = 0; i < CapabilityCount; i++)
    {
        OutputSaA[i].Attributes = Capabilities[i].Attributes;

        SidEntry = SepFindSharedSidEntry(Capabilities->Sid);

        if (SidEntry)
        {
            if (InterlockedIncrement64(&SidEntry->ReferCount) <= 1)
            {
                RtlFailFast(FAST_FAIL_INVALID_REFERENCE_COUNT);
                //never return 
            }

            Sid = SidEntry->Sid;
        }
        else
        {
            SidEntrySize = (((PISID)(Capabilities[i].Sid))->SubAuthorityCount * sizeof(ULONG) + FIELD_OFFSET(SID, SubAuthority) + sizeof(SHARED_SID_ENTRY)) * 2; //why mul by 2?

            SidEntry = (PSHARED_SID_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, SidEntrySize, SEP_SID_SHARING_TAG);

            if (SidEntry == NULL)
            {
                Status = STATUS_NO_MEMORY; 
                break; 
            }

            SidEntry->Sid = (PSID)((ULONG_PTR)SidEntry + sizeof(SHARED_SID_ENTRY));
            SidEntry->ReferCount = 1;

            //SidEntrySize was multiplied by 2 but here it's only subtracting a single structure size

            RtlCopySid(SidEntrySize - sizeof(SHARED_SID_ENTRY), (PSID)((ULONG_PTR)SidEntry + sizeof(SHARED_SID_ENTRY)), Capabilities[i].Sid);
            
            Signature = SID_HASH_ULONG(Capabilities[i].Sid);

            if (Signature == 0)
            {
                Signature = 1; 
            }

            if (RtlInsertEntryHashTable(g_SepSidMapping->HashTable, &SidEntry->Entry, Signature, NULL) == FALSE)
            {
                Status = STATUS_UNSUCCESSFUL; 
                ExFreePoolWithTag(SidEntry, SEP_SID_SHARING_TAG);
                break; 
            }
        }

        //output inserted or referenced sid entry

        OutputSaA[i].Sid = SidEntry->Sid;
    }

    //capability list not fully processed 
    if (i != CapabilityCount)
    {
        for (; i; i--)
        {
            //it must be able to find in the shared sid table

            SidEntry = SepFindSharedSidEntry(OutputSaA->Sid);
            
     
            RefCount = InterlockedDecrement64(&SidEntry->ReferCount);

            if (RefCount <= 0)
            {
                if (RefCount)
                {
                    RtlFailFast(FAST_FAIL_INVALID_REFERENCE_COUNT);
                    //never return
                }

                //reference count == 0 

                if (RtlRemoveEntryHashTable(g_SepSidMapping->HashTable, &SidEntry->Entry, NULL))
                {
                    ExFreePool(SidEntry);
                }
            }

            OutputSaA++;
        }
    }

    ExReleasePushLockExclusive(&g_SepSidMapping->Lock);
    
    KeLeaveCriticalRegion();

    return Status; 
}

NTSTATUS SepSetTokenCapabilities(
    PTOKEN Token,
    PISID Sid,
    PSID_AND_ATTRIBUTES CapabilityArray,
    ULONG CapabilityCount)
{
    NTSTATUS Status;
    unsigned int CapLength;
    PVOID CaptureBuffer;
    PSID Package;
    PSID_AND_ATTRIBUTES CapturedCap;
    ULONG CapturedSize;

    CapturedSize = 0;
    CapturedCap = NULL;

    if (Token->Capabilities)
    {
        if (Sid == NULL)
        {
            return STATUS_ACCESS_DENIED;
        }

        Package = Token->Package;

        if (Package)
        {
            if (!RtlIsParentOfChildAppContainer(Package, Sid))
            {
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    if (CapabilityCount)
    {
        if (CapabilityCount > SEP_MAX_GROUP_COUNT)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (*(BOOLEAN*)(KernelSymbols.SepTokenCapabilitySidSharingEnabled))
        {
            CapLength = sizeof(SID_AND_ATTRIBUTES) * CapabilityCount * 2 ; //why mul by 2?
        }
        else
        {
            Status = SepLengthSidAndAttributesArray(CapabilityArray, CapabilityCount, &CapturedSize);

            if (!NT_SUCCESS(Status))
            {
                return Status;
            }

            CapLength = CapturedSize;
        }

        CaptureBuffer = ExAllocatePool2(POOL_FLAG_PAGED, CapLength, SEP_SID_SHARING_TAG);

        if (CaptureBuffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (*(BOOLEAN*)(KernelSymbols.SepTokenCapabilitySidSharingEnabled))
        {
            Status = SepInsertOrReferenceSharedSidEntries(CapabilityArray, (SID_AND_ATTRIBUTES*)CaptureBuffer, CapabilityCount);
        }
        else
        {
            Status = SeCaptureSidAndAttributesArray(
                CapabilityArray,
                CapabilityCount,
                KernelMode,
                CaptureBuffer,
                CapLength,
                PagedPool,
                FALSE,
                &CapturedCap,
                &CapturedSize);
        }

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(CaptureBuffer);
        }
        else
        {
            if (Token->Capabilities)
                SepFreeTokenCapabilities(Token);

            Token->Capabilities = CapturedCap;
            Token->CapabilityCount = CapabilityCount;
            RtlSidHashInitialize((PSID_AND_ATTRIBUTES)CaptureBuffer,  CapabilityCount, &Token->CapabilitiesHash);
        }
        return Status;
    }
    else
    {
        if (Token->Capabilities)
        {
            SepFreeTokenCapabilities(Token);
        }

        Token->Capabilities = NULL;
        Token->CapabilityCount = 0;
        
        //added 24h2, cleanup hash
        RtlZeroMemory(&Token->CapabilitiesHash, sizeof(SID_AND_ATTRIBUTES_HASH));
        return STATUS_SUCCESS;
    }

}

BOOLEAN SepSidInTokenSidHash(PSID_AND_ATTRIBUTES_HASH SidHash, PSID PrincipalSelfSid, PSID Sid, BOOLEAN DenyAce, BOOLEAN Restricted, BOOLEAN TokenIsOwner)
{
    PSID CurrentSid = Sid; 
    ULONG               SidLength;
    UCHAR              SidRevsion;
    UCHAR               Hash;
    SID_HASH_ENTRY      HashLookupEntry;
    ULONG               ByteIndex;
    UCHAR               ByteLocation;
    ULONG               Index; 
    PSID_AND_ATTRIBUTES pSAHash;
    ULONG               i;

    if (PrincipalSelfSid != NULL && RtlEqualSid(SePrincipalSelfSid, Sid)) 
    {
        CurrentSid = PrincipalSelfSid;
    }

    if (TokenIsOwner && RtlEqualSid(SeOwnerRightsSid, CurrentSid))
    {
        return TRUE;
    }

    if (SidHash == NULL || CurrentSid == NULL)
    {
        return FALSE; 
    }

    SidLength = SeLengthSid(CurrentSid);
    SidRevsion = ((PISID)CurrentSid)->Revision;

    Hash = AUTHZ_SID_HASH_BYTE(CurrentSid);
    HashLookupEntry = AUTHZ_SID_HASH_LOOKUP(SidHash->Hash, Hash);

    ByteIndex = 0; 

    while (HashLookupEntry)
    {
        ByteLocation = (UCHAR)HashLookupEntry;

        while (ByteLocation)
        {
            Index = SidHashByteToIndexLookupTable[ByteLocation];

            pSAHash = &SidHash->SidAttr[ByteIndex + Index];

            if (((PISID)(pSAHash->Sid))->Revision == SidRevsion &&
                ((PISID)(pSAHash->Sid))->SubAuthorityCount == ((PISID)CurrentSid)->SubAuthorityCount)
            {
                if (memcmp(CurrentSid, pSAHash->Sid, SidLength) == 0)
                {
                    goto GetHashSA;
                }
            }

            ByteLocation = ByteLocation ^ (1 << Index);

        }

        ByteIndex += 8; 
        HashLookupEntry >>= 8; 
    }

    if (SidHash->SidCount > AUTHZI_SID_HASH_ENTRY_NUM_BITS)
    {
        for (i = AUTHZI_SID_HASH_ENTRY_NUM_BITS; i < SidHash->SidCount; i++)
        {
            pSAHash = &SidHash->SidAttr[i];

            if (((PISID)(pSAHash->Sid))->Revision == SidRevsion &&
                ((PISID)(pSAHash->Sid))->SubAuthorityCount == ((PISID)CurrentSid)->SubAuthorityCount)
            {
                if (memcmp(CurrentSid, pSAHash->Sid, SidLength) == 0)
                {
                    goto GetHashSA;
                }
            }

        }
    }

    return FALSE; 

GetHashSA:

    if (Restricted == FALSE && pSAHash != SidHash->SidAttr)
    {
        if ((pSAHash->Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0)
        {
            return TRUE; 
        }

        if (DenyAce)
        {
            return TRUE;
        }
    }

    if ((pSAHash->Attributes & SE_GROUP_ENABLED) || (DenyAce && (pSAHash->Attributes & SE_GROUP_USE_FOR_DENY_ONLY)))
    {
        return TRUE;

    }
    else
    {
        return FALSE;
    }
}


NTSTATUS SepGetTokenSessionMapEntry(ULONG SessionId, BOOLEAN bInsert, PSEP_LOWBOX_NUMBER_MAPPING* pLowboxNumberMapping)
{
    PSESSION_LOWBOX_MAP MapEntry;
    PLIST_ENTRY entry;

    *pLowboxNumberMapping = NULL;

    //create list entry of lowbox map if it's not yet initialized 

    if (*(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap) == NULL)
    {
        if (bInsert == FALSE)
        {
            return STATUS_NOT_FOUND;
        }

        *(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap) = (PLIST_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(LIST_ENTRY), SEP_LOWBOX_SESSION_TAG);

        if (*(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap) == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        InitializeListHead(*(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap));
    }

    //find map entry 
    for (entry = (*(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap))->Flink; entry != *(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap); entry = entry->Flink)
    {
        MapEntry = (PSESSION_LOWBOX_MAP)CONTAINING_RECORD(entry, SESSION_LOWBOX_MAP, ListEntry);

        if (MapEntry->SessionId == SessionId)
        {
            *pLowboxNumberMapping = &MapEntry->LowboxMap;
            return STATUS_SUCCESS;
        }
    }

    if (bInsert == FALSE)
    {
        return STATUS_NOT_FOUND;
    }

    //insert new entry 

    MapEntry = (PSESSION_LOWBOX_MAP)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(SESSION_LOWBOX_MAP), SEP_LOWBOX_SESSION_TAG);

    if (MapEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializePushLock(&MapEntry->LowboxMap.Lock);
    MapEntry->LowboxMap.Active = 0;
    MapEntry->SessionId = SessionId;

    //insert into map list
    InsertHeadList(*(PLIST_ENTRY*)(KernelSymbols.g_SessionLowboxMap), &MapEntry->ListEntry);

    *pLowboxNumberMapping = &MapEntry->LowboxMap;

    return STATUS_SUCCESS;
}

#define LOWBOX_BITMAP_BITS 1024
NTSTATUS SepInitializeLowBoxNumberTable(PSEP_LOWBOX_NUMBER_MAPPING LowboxNumberMapping)
{
    PVOID BitmapPool;

    LowboxNumberMapping->HashTable = NULL;

    if (RtlCreateHashTable(&LowboxNumberMapping->HashTable, 0, 0) == FALSE)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BitmapPool = ExAllocatePool2(POOL_FLAG_PAGED, LOWBOX_BITMAP_BITS / 8, SEP_LOWBOX_SESSION_TAG);

    if (BitmapPool == NULL)
    {
        RtlDeleteHashTable(LowboxNumberMapping->HashTable);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        LowboxNumberMapping->Bitmap.SizeOfBitMap = LOWBOX_BITMAP_BITS;
        LowboxNumberMapping->Bitmap.Buffer = BitmapPool;
        RtlClearAllBits(&LowboxNumberMapping->Bitmap);
        LowboxNumberMapping->Active = 1;
    }

    return STATUS_SUCCESS;

}
VOID SepFindMatchingLowBoxNumberEntry(PRTL_DYNAMIC_HASH_TABLE HashTable, PISID Sid, PSEP_LOWBOX_NUMBER_ENTRY* pLowboxNumberEntry)
{
    RTL_DYNAMIC_HASH_TABLE_CONTEXT Context;
   ULONG Signature;
    PRTL_DYNAMIC_HASH_TABLE_ENTRY Curr;
    BOOLEAN bFound = FALSE;

    RtlZeroMemory(&Context, sizeof(Context));

    Signature = SID_HASH_ULONG(Sid);

    if (Signature == 0)
    {
        Signature = 1;
    }

    for (Curr = RtlLookupEntryHashTable(HashTable, Signature, &Context); Curr != NULL; Curr = RtlGetNextEntryHashTable(HashTable, &Context))
    {
        if (RtlEqualSid(Sid, CONTAINING_RECORD(Curr, SEP_LOWBOX_NUMBER_ENTRY, HashEntry)->PackageSid))
        {
            bFound = TRUE;
            break;
        }
    }

    *pLowboxNumberEntry = bFound ? CONTAINING_RECORD(Curr, SEP_LOWBOX_NUMBER_ENTRY, HashEntry) : NULL;

    return;
}
#define MAX_LOWBOX_BITMAP_GROW_SIZE 0x10000
NTSTATUS SepGetLowBoxNumberEntry(PSEP_LOWBOX_NUMBER_MAPPING LowboxNumberMapping, PISID PackageSid, PSEP_LOWBOX_NUMBER_ENTRY* pLowboxNumberEntry)
{
    PSEP_LOWBOX_NUMBER_ENTRY Entry = NULL;
    ULONG NewEntryLength;
    ULONG BitStartingIndex;
    ULONG NewBitsCount;
    PVOID NewBitmapBuffer;
    ULONG HashTableSignature;

    //find for existing entry take package sid as key

    SepFindMatchingLowBoxNumberEntry(LowboxNumberMapping->HashTable, PackageSid, &Entry);

    //lowbox number with same sid exists

    if (Entry)
    {
        if (InterlockedIncrement64( & Entry->ReferenceCount) <= 1)
        {
            RtlFailFast(FAST_FAIL_INVALID_REFERENCE_COUNT);
            //never return
        }
        *pLowboxNumberEntry = Entry;
        return STATUS_SUCCESS;
    }

    //create new lowbox number

    //calcaute entry size

    NewEntryLength = LongAlignSize(SeLengthSid(PackageSid) + sizeof(SEP_LOWBOX_NUMBER_ENTRY));

    Entry = ExAllocatePool2(POOL_FLAG_PAGED, NewEntryLength, SEP_LOWBOX_SESSION_TAG);

    if (Entry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //Copy package SID content

    Entry->PackageSid = (PISID)((ULONG_PTR)Entry + sizeof(SEP_LOWBOX_NUMBER_ENTRY));
    RtlCopySid(NewEntryLength - sizeof(SEP_LOWBOX_NUMBER_ENTRY), (PISID)((ULONG_PTR)Entry + sizeof(SEP_LOWBOX_NUMBER_ENTRY)), PackageSid);

    BitStartingIndex = RtlFindClearBitsAndSet(&LowboxNumberMapping->Bitmap, 1, 0);

    //all bits are dirty, grow a new bitmap

    if (BitStartingIndex == 0xFFFFFFFF)
    {
        //Double the bitmap size

        NewBitsCount = 2 * RtlNumberOfSetBits(&LowboxNumberMapping->Bitmap);

        if (NewBitsCount > MAX_LOWBOX_BITMAP_GROW_SIZE)
        {
            ExFreePool(Entry);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NewBitmapBuffer = ExAllocatePool2(POOL_FLAG_PAGED, NewBitsCount / 8, SEP_LOWBOX_SESSION_TAG);

        if (NewBitmapBuffer == NULL)
        {
            ExFreePool(Entry);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //free the old buffer 
        ExFreePool(LowboxNumberMapping->Bitmap.Buffer);

        LowboxNumberMapping->Bitmap.SizeOfBitMap = NewBitsCount;
        LowboxNumberMapping->Bitmap.Buffer = NewBitmapBuffer;

        RtlClearAllBits(&LowboxNumberMapping->Bitmap);

        //reset previous bits
        RtlSetBits(&LowboxNumberMapping->Bitmap, 0, NewBitsCount / 2);

        BitStartingIndex = RtlFindClearBitsAndSet(&LowboxNumberMapping->Bitmap, 1, 0);

        //sorry what??

        if (BitStartingIndex == 0xFFFFFFFF)
        {
            ExFreePool(Entry);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (BitStartingIndex >= MAX_LOWBOX_BITMAP_GROW_SIZE - 1)
    {
        ExFreePool(Entry);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //insert new entry

    Entry->AtomTable = NULL;
    Entry->LowboxNumber = BitStartingIndex + 1;
    Entry->ReferenceCount = 1;

    HashTableSignature = SID_HASH_ULONG(PackageSid);

    if (HashTableSignature == 0)
    {
        HashTableSignature = 1;
    }

    if (RtlInsertEntryHashTable(LowboxNumberMapping->HashTable, &Entry->HashEntry, HashTableSignature, NULL) == FALSE)
    {
        ExFreePool(Entry);
        RtlClearBits(&LowboxNumberMapping->Bitmap, 1, BitStartingIndex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //Added reference to lowbox entry in 24h2, as it will be dereferenced again during token deletion in SepTokenDeleteMethod

    if (InterlockedIncrement64(&Entry->ReferenceCount) <= 1)
    {
        RtlFailFast(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }
    //end

    *pLowboxNumberEntry = Entry;
    return STATUS_SUCCESS;
}
#define GLOBAL_SESSION_LOWBOX_ARRAY_COUNT 5

//SEP_LOWBOX_NUMBER_MAPPING g_SessionLowboxArray[GLOBAL_SESSION_LOWBOX_ARRAY_COUNT];

NTSTATUS SepSetTokenLowboxNumber(PTOKEN Token, PISID PackageSid)
{
    ULONG SessionId = Token->SessionId;
    BOOLEAN bLockedShared = FALSE;
    BOOLEAN bLockedExclusive = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;
    PSEP_LOWBOX_NUMBER_MAPPING LowboxNumberMapping = NULL;
    PSEP_LOWBOX_NUMBER_ENTRY LowboxNumberEntry = NULL;

    if (SessionId < GLOBAL_SESSION_LOWBOX_ARRAY_COUNT)
    {
        LowboxNumberMapping = &((SEP_LOWBOX_NUMBER_MAPPING*)(KernelSymbols.g_SessionLowboxArray))[SessionId];
    }
    else
    {
        KeEnterCriticalRegion();

        ExAcquirePushLockShared((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));

        bLockedShared = TRUE;

        Status = SepGetTokenSessionMapEntry(SessionId, FALSE, &LowboxNumberMapping);

        if (!NT_SUCCESS(Status))
        {
            if (Status != STATUS_NOT_FOUND)
            {
                ExReleasePushLockShared((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));
                KeLeaveCriticalRegion();
                return Status;
            }

            ExReleasePushLockShared((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));
            KeLeaveCriticalRegion();

            KeEnterCriticalRegion();

            ExAcquirePushLockExclusive((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));

            Status = SepGetTokenSessionMapEntry(SessionId, TRUE, &LowboxNumberMapping);

            bLockedShared = FALSE;
            bLockedExclusive = TRUE;

            if (!NT_SUCCESS(Status))
            {
                ExReleasePushLockExclusive((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));
                KeLeaveCriticalRegion();
                return Status;
            }
        }
    }

    if (LowboxNumberMapping->Active == 0)
    {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&LowboxNumberMapping->Lock);
        if (LowboxNumberMapping->Active == 0)
        {
            Status = SepInitializeLowBoxNumberTable(LowboxNumberMapping);
        }

        ExReleasePushLockExclusive(&LowboxNumberMapping->Lock);
        KeLeaveCriticalRegion();
    }

    if (Status == STATUS_SUCCESS)
    {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&LowboxNumberMapping->Lock);

        Status = SepGetLowBoxNumberEntry(LowboxNumberMapping, PackageSid, &LowboxNumberEntry);

        if (Status == STATUS_SUCCESS)
        {
            Token->LowboxNumberEntry = LowboxNumberEntry;
        }

        ExReleasePushLockExclusive(&LowboxNumberMapping->Lock);
        KeLeaveCriticalRegion();
    }

    if (bLockedExclusive)
    {
        ExReleasePushLockExclusive((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));
        KeLeaveCriticalRegion();
    }
    else if (bLockedShared)
    {
        ExReleasePushLockShared((EX_PUSH_LOCK*)(KernelSymbols.LowboxSessionMapLock));
        KeLeaveCriticalRegion();
    }

    return Status;
}
NTSTATUS SepReferenceCachedTokenHandles(ULONG HandleCount , HANDLE* Handles , HANDLE* NewHandles)
{
    NTSTATUS status; 
    ULONG i;

    status = STATUS_SUCCESS; 

    for (i = 0 ; i < HandleCount ; i++)
    {
        status = ZwDuplicateObject(NtCurrentProcess(), Handles[i], NtCurrentProcess(), &NewHandles[i], 0, OBJ_KERNEL_HANDLE, DUPLICATE_SAME_ACCESS);

        if (!NT_SUCCESS(status))
        {
            break;
        }
    }

    if (i == HandleCount)
    {
        return status; 
    }

    for (; i != 0; i--)
    {
        ZwClose(NewHandles[i]);
    }

    return status;
}

NTSTATUS SepQueryNameString(PVOID Object , POBJECT_NAME_INFORMATION* ObjectNameInfo)
{
    NTSTATUS Status;
    POBJECT_NAME_INFORMATION NameInfo; 
    ULONG ReturnLength = 0; 
        
    *ObjectNameInfo = NULL;
   
    Status = ObQueryNameString(Object, NULL, 0, &ReturnLength);

    if (Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_TOO_SMALL)
    {
        NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, ReturnLength, SEP_OBJECT_NAME_INFORMATION_TAG);

        *ObjectNameInfo = NameInfo;

        if (NameInfo)
        {
            Status = ObQueryNameString(Object, NameInfo, ReturnLength, &ReturnLength);

            if (!NT_SUCCESS(Status) || NameInfo->Name.Length == 0)
            {
                ExFreePool(NameInfo);

                *ObjectNameInfo = NULL; 

                if (NT_SUCCESS(Status) && ObGetObjectType(Object) == *PsProcessType)
                {
                    SeLocateProcessImageName((PEPROCESS)Object,(PUNICODE_STRING*)ObjectNameInfo);
                }
                return STATUS_SUCCESS; 
            }
        }
        else
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    return Status;
}

NTSTATUS RtlGetAppContainerParent(PSID PackageSID , PISID* ParentSID)
{
    PISID ParentSid;
    NTSTATUS status;
    ULONG i; 
    APPCONTAINER_SID_TYPE SidType; 

    *ParentSID = NULL; 
    SidType = 0;
    
    if (!NT_SUCCESS(RtlGetAppContainerSidType(PackageSID, &SidType)) || SidType != ChildAppContainerSidType)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ParentSid = (PISID)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_USE_QUOTA, RtlLengthRequiredSid(SECURITY_PARENT_PACKAGE_RID_COUNT), RTL_PRIVATE_BUFFER_TAG);

    if (ParentSid == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlInitializeSid(ParentSid, &RtlpAppPackageAuthority, SECURITY_PARENT_PACKAGE_RID_COUNT);

    if (!NT_SUCCESS(status))
    {
        ExFreePool(ParentSid);
        return status ;
    }

    for (i = 0; i < SECURITY_PARENT_PACKAGE_RID_COUNT; i++)
    {
        ParentSid->SubAuthority[i] = *RtlSubAuthoritySid(PackageSID, i);
    }

    *ParentSID = ParentSid; 

    return status;
}


UNICODE_STRING AllowedCachedObjectNames[] = {
    RTL_CONSTANT_STRING(L"Local"),
    RTL_CONSTANT_STRING(L"Global"),
    RTL_CONSTANT_STRING(L"RPC Control"),
    RTL_CONSTANT_STRING(L"Session"),
    RTL_CONSTANT_STRING(L"AppContainerNamedObjects")
};

NTSTATUS SepValidateReferencedCachedHandles(
    PTOKEN Token,
    SEP_CACHED_HANDLES_ENTRY_DESCRIPTOR* EntryDescriptor,
    ULONG HandleCount,
    HANDLE* NewHandles)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID Object = NULL; 
    ULONG AllowedDirectoryCount = 0; 
    POBJECT_TYPE ObjectType; 
    ULONG j;
    BOOLEAN bValid ;
    BOOLEAN bSidNameAllocated = FALSE; 
    PSID ParentSID; 
    APPCONTAINER_SID_TYPE SidType = 0;
    ULONG i; 
    POBJECT_NAME_INFORMATION NameInfo = NULL;
    PCUNICODE_STRING pPrefixName = NULL; 
    UNICODE_STRING ObjectName;
    UNICODE_STRING SidName = { 0, 0 , NULL };
    UNICODE_STRING HeaderObjectName; 
    POBJECT_HEADER_NAME_INFO HeaderNameInfo;
    ALLOWED_CACHED_DIRECTORY AllowedDirectories[2];
    WCHAR AllowedPath1[256];
    WCHAR ChildSidName[256];

    if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryBnoIsolation)
    {
        pPrefixName = &EntryDescriptor->u1.IsolationPrefix;

        status = RtlStringCchPrintfW(AllowedPath1, MAX_OBJECT_PATH ,  L"\\Sessions\\%d", Token->SessionId);

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        RtlInitUnicodeString(&AllowedDirectories[0].DirectoryName, AllowedPath1);
        
        AllowedDirectories[0].bCheckName = TRUE;
        AllowedDirectoryCount = 1; 

        if (Token->SessionId == RtlGetCurrentServiceSessionId())
        {
            RtlInitUnicodeString(&AllowedDirectories[1].DirectoryName, L"\\BaseNamedObjects");
            AllowedDirectories[1].bCheckName = TRUE;
            AllowedDirectoryCount = 2;
        }
    }
    else if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryLowbox)
    {
        status = RtlGetAppContainerSidType(EntryDescriptor->u1.PackageSid, &SidType);
        
        if (!NT_SUCCESS(status))
        {
            goto Exit; 
        }

        if (SidType == ParentAppContainerSidType)
        {
            status = RtlConvertSidToUnicodeString(&SidName, EntryDescriptor->u1.PackageSid, TRUE);

            if (!NT_SUCCESS(status))
            {
                goto Exit; 
            }

            bSidNameAllocated = TRUE; 
        }
        else
        {
            status = RtlStringCchPrintfW(ChildSidName,
                MAX_OBJECT_PATH,
                L"%u-%u-%u-%u",
                *RtlSubAuthoritySid(EntryDescriptor->u1.PackageSid, SECURITY_CHILD_PACKAGE_RID_COUNT - 4),
                *RtlSubAuthoritySid(EntryDescriptor->u1.PackageSid, SECURITY_CHILD_PACKAGE_RID_COUNT - 3),
                *RtlSubAuthoritySid(EntryDescriptor->u1.PackageSid, SECURITY_CHILD_PACKAGE_RID_COUNT - 2),
                *RtlSubAuthoritySid(EntryDescriptor->u1.PackageSid, SECURITY_CHILD_PACKAGE_RID_COUNT - 1));

            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            RtlInitUnicodeString(&SidName, ChildSidName);
        }

        pPrefixName = &SidName;

        status = RtlStringCchPrintfW(AllowedPath1, MAX_OBJECT_PATH, L"\\Sessions\\%d", Token->SessionId);
        
        if (!NT_SUCCESS(status))      
        {
            goto Exit; 
        }


        RtlInitUnicodeString(&AllowedDirectories[0].DirectoryName, AllowedPath1);

        AllowedDirectories[0].bCheckName = TRUE;

        RtlInitUnicodeString(&AllowedDirectories[1].DirectoryName, L"\\Device\\NamedPipe");

        AllowedDirectories[1].bCheckName = FALSE;

        AllowedDirectoryCount = 2; 
    }

    //For subsequent descriptor categorizations, execution continues without an explicit return. 
    //While not ideal, this is presently acceptable as the function has only two caller types in its invocation chain for now.


    for (i = 0; i < HandleCount; i++)
    {
       if (Object)
       {
           ObDereferenceObject(Object);
       }

       Object = NULL; 

       status = ObReferenceObjectByHandle(NewHandles[i], 0, NULL, KernelMode, &Object, NULL);

       if (!NT_SUCCESS(status))
       {
           continue; 
       }

       ObjectType = ObGetObjectType(Object);

       if (ObjectType != ObpSymbolicLinkObjectType && 
           ObjectType != ObpDirectoryObjectType && 
           (ObjectType != *IoFileObjectType || ((PFILE_OBJECT)Object)->DeviceObject->DeviceType != FILE_DEVICE_NAMED_PIPE ))
       {
           status = STATUS_INVALID_PARAMETER; 
           break; 
       }

       if (NameInfo)
       {
           ExFreePool(NameInfo);
           NameInfo = NULL;
       }

       status = SepQueryNameString(Object, &NameInfo);

       if (!NT_SUCCESS(status))
       {
           break;
       }

       if (NameInfo == NULL || NameInfo->Name.MaximumLength == 0)
       {
           status = STATUS_INVALID_PARAMETER;
           break; 
       }

       ObjectName = NameInfo->Name;

       for (j = 0; j < AllowedDirectoryCount; j++)
       {
           if (RtlPrefixUnicodeString(&AllowedDirectories[j].DirectoryName, &ObjectName, TRUE))
           {
               break; 
           }
       }

       if (j == AllowedDirectoryCount)
       {
           status = STATUS_INVALID_PARAMETER;
           break; 
       }

       if (AllowedDirectories[j].bCheckName)
       {
           HeaderNameInfo = ObQueryNameInfo(Object);

           if (HeaderNameInfo == NULL || HeaderNameInfo->Name.MaximumLength == 0)
           {
               status = STATUS_INVALID_PARAMETER;
               break; 
           }

           HeaderObjectName = HeaderNameInfo->Name;

           //Check object prefix name white list

           if (RtlEqualUnicodeString(&HeaderObjectName, pPrefixName, TRUE) == FALSE)
           {
               //Check object name white list

               for (j = 0; j < ARRAYSIZE(AllowedCachedObjectNames); j++)
               {
                   if (RtlEqualUnicodeString(&HeaderObjectName, &AllowedCachedObjectNames[j], TRUE))
                   {
                       break; 
                   }
               }

               if (j != ARRAYSIZE(AllowedCachedObjectNames))
               {
                   continue; 
               }

               //white list, object name = SID ?

               if (SidType != ChildAppContainerSidType)
               {
                   status = STATUS_INVALID_PARAMETER;
                   break; 
               }

               ParentSID = NULL;

               if (!NT_SUCCESS(RtlGetAppContainerParent(EntryDescriptor->u1.PackageSid, (PISID*)&ParentSID)))
               {
                   status = STATUS_INVALID_PARAMETER;
                   break;
               }

               ObjectName.Buffer = NULL;
               ObjectName.Length = 0;
               ObjectName.MaximumLength = 0;

               if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&ObjectName, ParentSID, TRUE)))
               {
                   status = STATUS_INVALID_PARAMETER;
                   break;

               }

               bValid = (RtlEqualUnicodeString(&HeaderObjectName, &ObjectName, TRUE) == TRUE);

               RtlFreeUnicodeString(&ObjectName);

               ExFreePool(ParentSID);

               if (bValid == FALSE)
               {
                   status = STATUS_INVALID_PARAMETER;
                   break;
               }
           }
       }
    }

Exit:
    if (NameInfo)
    {
        ExFreePool(NameInfo);
    }

    if (Object)
    {
        ObDereferenceObject(Object);
    }

    if (bSidNameAllocated)
    {
        RtlFreeUnicodeString(&SidName);
    }

    return status; 
}

NTSTATUS SepCloseCachedTokenHandles(ULONG HandleCount, HANDLE* Handles)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i; 

    for (i = 0; i < HandleCount; i++)
    {
        status = ZwClose(Handles[i]);
    }
    return status;
}

NTSTATUS SepAllocateAndInitializeCachedHandleEntry( PSEP_CACHED_HANDLES_ENTRY_DESCRIPTOR EntryDescriptor, PSEP_CACHED_HANDLES_ENTRY* HandlesEntryReturn)
{
    ULONG RequiredLength; 
    PSEP_CACHED_HANDLES_ENTRY Entry; 

    *HandlesEntryReturn = NULL;
    RequiredLength = sizeof(SEP_CACHED_HANDLES_ENTRY);

    if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryLowbox)
    {
        RequiredLength = RtlLengthRequiredSid(((PISID)EntryDescriptor->u1.PackageSid)->SubAuthorityCount) + sizeof(SEP_CACHED_HANDLES_ENTRY);
    }
    else if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryBnoIsolation)
    {
        RequiredLength = EntryDescriptor->u1.IsolationPrefix.MaximumLength + sizeof(SEP_CACHED_HANDLES_ENTRY);
    }

    Entry = (PSEP_CACHED_HANDLES_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, LongAlignSize(RequiredLength), 'sLeS');

    if (Entry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }


    Entry->Handles = NULL; 
    Entry->HandleCount = 0;
    Entry->ReferenceCount = 1; 
    Entry->EntryDescriptor.DescriptorType = EntryDescriptor->DescriptorType;

    if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryLowbox)
    {
        Entry->EntryDescriptor.u1.PackageSid = (PSID)((ULONG_PTR)Entry + sizeof(SEP_CACHED_HANDLES_ENTRY));
        RtlCopySid(RtlLengthRequiredSid(((PISID)EntryDescriptor->u1.PackageSid)->SubAuthorityCount),
            (PSID)((ULONG_PTR)Entry + sizeof(SEP_CACHED_HANDLES_ENTRY)), 
            EntryDescriptor->u1.PackageSid);
    }
    else
    {
        if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryBnoIsolation)
        {
            Entry->EntryDescriptor.u1.IsolationPrefix.Length = EntryDescriptor->u1.IsolationPrefix.Length;
            Entry->EntryDescriptor.u1.IsolationPrefix.MaximumLength = EntryDescriptor->u1.IsolationPrefix.MaximumLength;
            Entry->EntryDescriptor.u1.IsolationPrefix.Buffer = (WCHAR*)((ULONG_PTR)Entry + sizeof(SEP_CACHED_HANDLES_ENTRY));

            RtlCopyUnicodeString(&Entry->EntryDescriptor.u1.IsolationPrefix, &EntryDescriptor->u1.IsolationPrefix);

        }

    }
  
    *HandlesEntryReturn = Entry;
    return STATUS_SUCCESS; 
}
ULONG SepComputeCachedHandlesEntrySignature(PSEP_CACHED_HANDLES_ENTRY_DESCRIPTOR EntryDescriptor)
{
    ULONG HashValue; 

    if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryBnoIsolation)
    {
        RtlHashUnicodeString(&EntryDescriptor->u1.IsolationPrefix, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &HashValue);
    }
    else if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryLowbox)
    {
        HashValue = SID_HASH_ULONG(EntryDescriptor->u1.PackageSid);

        if (HashValue == 0)
        {
            HashValue = 1;
        }

        return HashValue;
    }

    return 0;
}
NTSTATUS SepFindMatchingCachedHandlesEntry(PRTL_DYNAMIC_HASH_TABLE HashTable, ULONG Signature, PSEP_CACHED_HANDLES_ENTRY_DESCRIPTOR EntryDescriptor, PSEP_CACHED_HANDLES_ENTRY* Entry)
{
    struct _RTL_DYNAMIC_HASH_TABLE_CONTEXT Context = { 0 };
    BOOLEAN bFound = FALSE; 
    PRTL_DYNAMIC_HASH_TABLE_ENTRY i;
    PSEP_CACHED_HANDLES_ENTRY HandlesEntry = NULL ;

    for (i = RtlLookupEntryHashTable(HashTable, Signature, &Context); i; i = RtlGetNextEntryHashTable(HashTable, &Context))
    {
        HandlesEntry = CONTAINING_RECORD(i, SEP_CACHED_HANDLES_ENTRY, HashEntry);

        if (EntryDescriptor->DescriptorType == HandlesEntry->EntryDescriptor.DescriptorType)
        {
            if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryLowbox)
            {
                if (RtlEqualSid(EntryDescriptor->u1.PackageSid, HandlesEntry->EntryDescriptor.u1.PackageSid))
                {
                    bFound = TRUE;
                    break;
                }
            }
            else if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryBnoIsolation)
            {
                if (RtlEqualUnicodeString(&EntryDescriptor->u1.IsolationPrefix, &HandlesEntry->EntryDescriptor.u1.IsolationPrefix, TRUE) == TRUE)
                {
                    bFound = TRUE;
                    break;
                }
            }
        }
    }

    if (bFound)
    {
        *Entry = HandlesEntry; 
    }
    else
    {
        *Entry = NULL; 
    }

    return STATUS_SUCCESS; 

}
NTSTATUS SepGetCachedHandlesEntry(PSEP_CACHED_HANDLES_TABLE HandleTable,
    PSEP_CACHED_HANDLES_ENTRY_DESCRIPTOR EntryDescriptor,
    BOOLEAN* bReferenced,
    PSEP_CACHED_HANDLES_ENTRY* EntryReturned)
{
    struct _RTL_DYNAMIC_HASH_TABLE* HashTable = HandleTable->HashTable;
    NTSTATUS Status; 
    ULONG HashValue = 0 ;
    PSEP_CACHED_HANDLES_ENTRY HandlesEntry = NULL;

    HashValue = SepComputeCachedHandlesEntrySignature(EntryDescriptor);

    *bReferenced = FALSE;

    HandlesEntry = NULL;

    SepFindMatchingCachedHandlesEntry(HashTable, HashValue, EntryDescriptor, &HandlesEntry);


    if (HandlesEntry)
    {
        if (InterlockedIncrement64(&HandlesEntry->ReferenceCount) <= 1)
        {
            RtlFailFast(FAST_FAIL_INVALID_REFERENCE_COUNT);
            //never return
        }
        *EntryReturned = HandlesEntry; 
        *bReferenced = TRUE;
        return STATUS_SUCCESS;
    }
    
    Status = SepAllocateAndInitializeCachedHandleEntry(EntryDescriptor, &HandlesEntry);

    if (!NT_SUCCESS(Status))
    {
        return Status; 
    }

    if (RtlInsertEntryHashTable(HashTable, &HandlesEntry->HashEntry, HashValue, NULL) == FALSE)
    {
        ExFreePool(HandlesEntry);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *EntryReturned = HandlesEntry;

    return STATUS_SUCCESS; 

}


NTSTATUS SepSetTokenCachedHandles(PTOKEN Token, SEP_CACHED_HANDLES_ENTRY_DESCRIPTOR* EntryDescriptor, ULONG HandleCount, HANDLE* Handles)
{
    HANDLE* NewHandles = NULL;
    BOOLEAN bHandleDuplicated = FALSE;
    NTSTATUS Status;
    SEP_CACHED_HANDLES_TABLE* SessionCachedHandlesTable;
    BOOLEAN bAddHandleTable;
    PSEP_CACHED_HANDLES_ENTRY Entry = NULL; 
     BOOLEAN bReferenced = FALSE; 

    if (HandleCount)
    {
        NewHandles = (HANDLE*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(HANDLE) * HandleCount, 'cHeS');

        if (NewHandles == NULL)
        {
            return STATUS_NO_MEMORY;
        }

        Status = SepReferenceCachedTokenHandles(HandleCount, Handles, NewHandles);

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(NewHandles);
            return Status;
        }

        bHandleDuplicated = TRUE;

        Status = SepValidateReferencedCachedHandles(Token, EntryDescriptor, HandleCount, NewHandles);

        if (!NT_SUCCESS(Status))
        {
            SepCloseCachedTokenHandles(HandleCount, NewHandles);
            ExFreePool(NewHandles);
            return Status;
        }
    }

    KeEnterCriticalRegion();
    SessionCachedHandlesTable = &Token->LogonSession->CachedHandlesTable;

    ExAcquirePushLockExclusive(&SessionCachedHandlesTable->Lock);
    

    if (SessionCachedHandlesTable->HashTable == NULL)
    {
        if (RtlCreateHashTable(&SessionCachedHandlesTable->HashTable, 0, 0) == FALSE)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit; 
        }
    }

    Status = SepGetCachedHandlesEntry(SessionCachedHandlesTable, EntryDescriptor, &bReferenced, &Entry);

    if (Status != STATUS_SUCCESS)
    {
        goto Exit;
    }


    bAddHandleTable = FALSE; 

    if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryLowbox)
    {
        Token->LowboxHandlesEntry = Entry;
        if (HandleCount && Entry->HandleCount == 0)
        {
            bAddHandleTable = TRUE; 
        }
    }
    else if (EntryDescriptor->DescriptorType == SepCachedHandlesEntryBnoIsolation)
    {
        Token->BnoIsolationHandlesEntry = Entry; 
    
        if (bReferenced == FALSE)
        {
            bAddHandleTable = TRUE; 
        }
    }

    if (bAddHandleTable)
    {
        Entry->HandleCount = HandleCount; 
        Entry->Handles = (PVOID)NewHandles; 
    }

    bHandleDuplicated = FALSE; 

    NewHandles = NULL; 

Exit:
    ExReleasePushLockExclusive(&SessionCachedHandlesTable->Lock);
    KeLeaveCriticalRegion();

    if (NewHandles)
    {
        if (bHandleDuplicated)
        {
            SepCloseCachedTokenHandles(HandleCount, NewHandles);
        }

        ExFreePool(NewHandles);
    }

    return Status; 
}

NTSTATUS SepSetTokenPackage(PTOKEN Token , PISID PackageSid)
{
    ULONG SidLength; 
    PSID NewSid; 

    if (Token->Package && RtlIsParentOfChildAppContainer(Token->Package, PackageSid) == FALSE)
    {
        return STATUS_ACCESS_DENIED;
    }

    SidLength = LongAlignSize(SeLengthSid(PackageSid));

    NewSid = (PSID)ExAllocatePool2(POOL_FLAG_PAGED, SidLength, SEP_SID_TAG);


    if (NewSid == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopySid(SidLength , NewSid , PackageSid);

    if (Token->Package)
    {
        ExFreePool(Token->Package);
    }

    Token->Package = NewSid;

    return STATUS_SUCCESS; 
}

PACE_HEADER RtlFindAceBySid(PACL pAcl, PSID pSid, PULONG pIndex)
{
    ULONG i;
    PACE_HEADER pAce;
    PSID AceSid; 

    if (pAcl == NULL)
    {
        return NULL; 
    }

    for (i = 0, pAce = FirstAce(pAcl); i < pAcl->AceCount; i++, pAce = NextAce(pAce))
    {
        if (IsAllowedAceType(pAce))
        {
            AceSid = (PSID) & (((PACCESS_ALLOWED_ACE)pAce)->SidStart);
        }
        else if (IsCompoundAceType(pAce))
        {
            AceSid = (PSID) & (((PKNOWN_COMPOUND_ACE)pAce)->SidStart);
        }
        else if (IsObjectAceType(pAce) || IsCallbackObjectAceType(pAce) || IsSytstemCallbackObjectAceType(pAce))
        {
            AceSid = RtlObjectAceSid(pAce);
        }
        else
        {
            AceSid = NULL;
        }

        if (AceSid)
        {
            if (pIndex == NULL)
            {
                if (RtlEqualSid(AceSid, pSid))
                {
                    return pAce;
                }
            }
            else
            {
                if (i >= *pIndex && RtlEqualSid(AceSid, pSid))
                {
                    *pIndex = i;
                    return pAce;
                }
            }
        }
    }

    return NULL;
}

NTSTATUS SepExpandDynamic(PTOKEN Token, ULONG NewLength)
{
    ULONG CurrentSize; 
    PVOID NewDynamic; 
    PVOID DynamicPart;

    CurrentSize = Token->DynamicAvailable + SeLengthSid(Token->PrimaryGroup);

    if (Token->DefaultDacl)
    {
        CurrentSize += Token->DefaultDacl->AclSize;
    }

    if (NewLength <= CurrentSize)
    {
        STATUS_SUCCESS; 
    }

    NewDynamic = ExAllocatePool2(POOL_FLAG_PAGED, NewLength, SEP_TOKEN_DYNAMIC_PART_TAG);
 
    if (NewDynamic == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DynamicPart = Token->DynamicPart;

    RtlCopyMemory(NewDynamic, DynamicPart, CurrentSize);

    Token->DynamicAvailable += NewLength - CurrentSize;
    Token->DynamicPart = NewDynamic;

    if (Token->DefaultDacl)
    {
        Token->DefaultDacl = (PACL)((PUCHAR)NewDynamic + ((PUCHAR)Token->DefaultDacl - (PUCHAR)DynamicPart));
    }

    Token->PrimaryGroup = (PSID)((PUCHAR)NewDynamic + ((PUCHAR)Token->PrimaryGroup - (PUCHAR)DynamicPart));
   
    ExFreePool(DynamicPart);

    return STATUS_SUCCESS; 

}

VOID SepFreeDefaultDacl(PTOKEN Token)
{
    if (Token->DefaultDacl)
    {
        Token->DynamicAvailable += Token->DefaultDacl->AclSize;
        Token->DefaultDacl = NULL;
    }

    if (Token->DynamicPart != (PULONG)Token->PrimaryGroup)
    {
        RtlMoveMemory((PVOID)(Token->DynamicPart), (PVOID)(Token->PrimaryGroup), SeLengthSid(Token->PrimaryGroup));

        Token->PrimaryGroup = (PSID)Token->DynamicPart;
    }

    return;
}

VOID SepAppendDefaultDacl(PTOKEN Token, PACL NewAcl)
{
    RtlCopyMemory((PVOID)((ULONG_PTR)(Token->DynamicPart) + SeLengthSid(Token->PrimaryGroup)), (PVOID)NewAcl, NewAcl->AclSize);

    Token->DynamicAvailable -= NewAcl->AclSize; 
    Token->DefaultDacl = (PACL)(PVOID)((ULONG_PTR)(Token->DynamicPart) + SeLengthSid(Token->PrimaryGroup));
    return; 
}

NTSTATUS SepAppendAceToTokenDefaultDacl(PTOKEN Token, PISID PackageSid)
{
    PACL DefaultAcl; 
    NTSTATUS Status; 
    ULONG LengthRequired;
    PACL NewAcl = NULL; 
    ACL_REVISION_INFORMATION AclRevision = { 0 };
    PVOID Ace = NULL; 
    ACL_SIZE_INFORMATION AclSize = { 0 , 0 , 0 };

    DefaultAcl = Token->DefaultDacl; 

    if (DefaultAcl == NULL || RtlFindAceBySid(DefaultAcl, PackageSid, NULL))
    {
        return STATUS_SUCCESS;
    }
    else
    {
        Status = RtlQueryInformationAcl(DefaultAcl, &AclRevision, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);

        if (!NT_SUCCESS(Status))
        {
            return Status; 
        }

        Status = RtlQueryInformationAcl(DefaultAcl, &AclSize, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

        if (!NT_SUCCESS(Status))
        {
            return Status;
        }


        LengthRequired = LongAlignSize(DefaultAcl->AclSize + SeLengthSid(PackageSid) + sizeof(ACL));


        NewAcl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED , LengthRequired , SEP_ACL_TAG);
           
        if (NewAcl == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = RtlCreateAcl(NewAcl, LengthRequired, AclRevision.AclRevision);

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(NewAcl);
            return Status;
        }

        Status = RtlGetAce(DefaultAcl, 0, &Ace);

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(NewAcl);
            return Status;
        }

        Status = RtlAddAce(NewAcl, AclRevision.AclRevision, 0, Ace, AclSize.AclBytesInUse - sizeof(ACL));

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(NewAcl);
            return Status;
        }

        Status = RtlAddAccessAllowedAce(NewAcl, AclRevision.AclRevision, GENERIC_ALL,  PackageSid);


        if (!NT_SUCCESS(Status))
        {
            ExFreePool(NewAcl);
            return Status;
        }
       
        Status = SepExpandDynamic(Token, LongAlignSize(LengthRequired + SeLengthSid(Token->PrimaryGroup)));

        if (!NT_SUCCESS(Status))
        {
            ExFreePool(NewAcl);
            return Status;
        }
        
        SepFreeDefaultDacl(Token);
        SepAppendDefaultDacl(Token , NewAcl);


        ExFreePool(NewAcl);
    }

    return Status;
}

BOOLEAN SepCapabilitiesHasAppSiloBaseSID(ULONG CapabilityCount , SID_AND_ATTRIBUTES* Capabilities)
{
    ULONG Index;

    for (Index = 0; Index < CapabilityCount; Index++)
    {
        if (RtlEqualSid(SeAppSiloSid, Capabilities[Index].Sid))
        {
            return TRUE;
        }
    }

    return FALSE;
}

PSID_IDENTIFIER_AUTHORITY
_RtlIdentifierAuthoritySid(
    IN PSID Sid
)
/*++

Routine Description:

    This function returns the address of an SID's IdentifierAuthority field.

Arguments:

    Sid - Pointer to the SID data structure.

Return Value:


--*/
{
    PISID ISid;

    //
    //  Typecast to the opaque SID
    //

    ISid = (PISID)Sid;

    return &(ISid->IdentifierAuthority);

}

BOOLEAN SepIsAppSiloCapability(PSID CapSID)
{
    PSID_IDENTIFIER_AUTHORITY CapIDAUTH, AppSiloCapIDAUTH; 
    ULONG Index ;

    if (((PISID)CapSID)->Revision != ((PISID)SeAppSiloSid)->Revision ||
        ((PISID)CapSID)->SubAuthorityCount <= ((PISID)SeAppSiloSid)->SubAuthorityCount)
    {
        return FALSE; 
    }
    AppSiloCapIDAUTH = _RtlIdentifierAuthoritySid(SeAppSiloSid);
    CapIDAUTH = _RtlIdentifierAuthoritySid(CapSID);

    if (memcmp(&CapIDAUTH, &AppSiloCapIDAUTH, sizeof(SID_IDENTIFIER_AUTHORITY)) == 0)
    {
        Index = 0; 

        while (Index < ((PISID)SeAppSiloSid)->SubAuthorityCount)
        {
            if (((PISID)CapSID)->SubAuthority[Index] != ((PISID)SeAppSiloSid)->SubAuthority[Index])
            {
                return FALSE;
            }
            Index++;
        }
    }
    return TRUE; 
}

//we just import this function cause ObsSecurityDescriotCahce involved 
VOID NTSYSAPI
ObDereferenceSecurityDescriptor(
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in ULONG Count
);

BOOLEAN NTSYSAPI RtlValidAcl(IN PACL Acl);
BOOLEAN NTSYSAPI RtlFirstFreeAce(IN PACL Acl, OUT PVOID* FirstFree);

NTSTATUS
RtlpAddKnownAce(
    IN OUT PACL Acl,
    IN ULONG AceRevision,
    IN ULONG AceFlags,
    IN ACCESS_MASK AccessMask,
    IN PSID Sid,
    IN UCHAR NewType
)

/*

Routine Description:

    This routine adds KNOWN_ACE to an ACL.  This is
    expected to be a common form of ACL modification.

    A very bland ACE header is placed in the ACE.  It provides no
    inheritance and no ACE flags.  The type is specified by the caller.

Arguments:

    Acl - Supplies the Acl being modified

    AceRevision - Supplies the Acl/Ace revision of the ACE being added

    AceFlags - Supplies the inherit flags for the ACE.

    AccessMask - The mask of accesses to be denied to the specified SID.

    Sid - Pointer to the SID being denied access.

    NewType - Type of ACE to be added.

Return Value:

    STATUS_SUCCESS - The ACE was successfully added.

    STATUS_INVALID_ACL - The specified ACL is not properly formed.

    STATUS_REVISION_MISMATCH - The specified revision is not known
        or is incompatible with that of the ACL.

    STATUS_ALLOTTED_SPACE_EXCEEDED - The new ACE does not fit into the
        ACL.  A larger ACL buffer is required.

    STATUS_INVALID_SID - The provided SID is not a structurally valid
        SID.

    STATUS_INVALID_PARAMETER - The AceFlags parameter was invalid.

*/

{
    PVOID FirstFree;
    USHORT AceSize;
    PKNOWN_ACE GrantAce;
    UCHAR NewRevision;
    ULONG TestedAceFlags;


    // Validate the structure of the SID


    if (!RtlValidSid(Sid)) 
    {
        return STATUS_INVALID_SID;
    }


    //  Check the ACL & ACE revision levels


    if (Acl->AclRevision > ACL_REVISION4 || AceRevision > ACL_REVISION4) 
    {

        return STATUS_REVISION_MISMATCH;
    }


    // Calculate the new revision of the ACL.  The new revision is the maximum
    // of the old revision and and new ACE's revision.  This is possible because
    // the format of previously defined ACEs did not change across revisions.


    NewRevision = Acl->AclRevision > (UCHAR)AceRevision ? Acl->AclRevision : (UCHAR)AceRevision;


    // Validate the AceFlags.


    TestedAceFlags = AceFlags & ~VALID_INHERIT_FLAGS;

    if (TestedAceFlags != 0) 
    {

        if (NewType == SYSTEM_AUDIT_ACE_TYPE)
        {
            TestedAceFlags &= ~(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);
        }
        else if (NewType == ACCESS_ALLOWED_ACE_TYPE)
        {
            TestedAceFlags &= ~(CRITICAL_ACE_FLAG);
        }

        if (TestedAceFlags != 0) 
        {
            return STATUS_INVALID_PARAMETER;
        }
    }


    //  Locate the first free ace and check to see that the Acl is
    //  well formed.


    if (!RtlValidAcl(Acl))
    {
        return STATUS_INVALID_ACL;
    }

    if (!RtlFirstFreeAce(Acl, &FirstFree))
    {

        return STATUS_INVALID_ACL;
    }


    //  Check to see if there is enough room in the Acl to store the new
    //  ACE


    AceSize = (USHORT)(sizeof(ACE_HEADER) +  sizeof(ACCESS_MASK) + SeLengthSid(Sid));

    if (FirstFree == NULL || ((PUCHAR)FirstFree + AceSize > ((PUCHAR)Acl + Acl->AclSize)))
    {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }


    // Add the ACE to the end of the ACL


    GrantAce = (PKNOWN_ACE)FirstFree;
    GrantAce->Header.AceFlags = (UCHAR)AceFlags;
    GrantAce->Header.AceType = NewType;
    GrantAce->Header.AceSize = AceSize;
    GrantAce->Mask = AccessMask;

    RtlCopySid(SeLengthSid(Sid), (PSID)(&GrantAce->SidStart), Sid);


    // Increment the number of ACEs by 1.


    Acl->AceCount += 1;


    // Adjust the Acl revision, if necessary


    Acl->AclRevision = NewRevision;


    //  And return to our caller


    return STATUS_SUCCESS;
}
NTSTATUS NTSYSAPI RtlAddAce(PACL Acl, ULONG AceRevision, ULONG StartingAceIndex, PVOID AceList, ULONG AceListLength);
NTSTATUS NTSYSAPI ObSetSecurityObjectByPointer(__in PVOID Object, __in SECURITY_INFORMATION SecurityInformation, __in PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSTATUS SepAppendAceToTokenObjectAcl(PTOKEN Token , ACCESS_MASK Access , PSID Sid)
{  
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL ;
    BOOLEAN MemoryAllocated = FALSE;
    NTSTATUS Status = STATUS_SUCCESS; 
    PACL TokenDacl; 
    ULONG AclSize; 
    SECURITY_DESCRIPTOR NewSecurityDescriptor = { 0 };
    ACL_SIZE_INFORMATION AclSizeInfo; 
    ACL_REVISION_INFORMATION RevisionInfo; 
    PACL NewDacl = NULL; 
    PVOID Ace = NULL; 

    Status = ObGetObjectSecurity(Token, &SecurityDescriptor, &MemoryAllocated);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (SecurityDescriptor == NULL)
    {
        return Status; 
    }

    TokenDacl = RtlpDaclAddrSecurityDescriptor((PISECURITY_DESCRIPTOR)SecurityDescriptor);

    if (TokenDacl == NULL)
    {
        goto Exit; 
    }

    //Make sure no such ACE exists in the original token dacl

    if (RtlFindAceBySid(TokenDacl, Sid, NULL))
    {
        goto Exit; 
    }
    
    Status = RtlQueryInformationAcl(TokenDacl, &AclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

    if (!NT_SUCCESS(Status))
    {
        goto Exit; 
    }

    Status = RtlQueryInformationAcl(TokenDacl, &RevisionInfo, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);

    if (!NT_SUCCESS(Status))
    {
        goto Exit; 
    }

    AclSize = LongAlignSize(AclSizeInfo.AclBytesInUse + RtlLengthSid(Sid) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart));

    NewDacl = (PACL) ExAllocatePool2(POOL_FLAG_PAGED, AclSize, SEP_ACL_TAG);

    if (NewDacl == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit; 
    }

    Status = RtlCreateAcl(NewDacl, AclSize, RevisionInfo.AclRevision);

    if (!NT_SUCCESS(Status))
    {
        goto Exit; 
    }

    Status = RtlGetAce(TokenDacl, 0, &Ace);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = RtlAddAce(NewDacl, RevisionInfo.AclRevision, 0, Ace, AclSizeInfo.AclBytesInUse - sizeof(ACL));

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = RtlpAddKnownAce(NewDacl, RevisionInfo.AclRevision, 0, Access, Sid, ACCESS_ALLOWED_ACE_TYPE);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = RtlCreateSecurityDescriptor(&NewSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = RtlSetDaclSecurityDescriptor(&NewSecurityDescriptor, TRUE, TokenDacl, FALSE);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = ObSetSecurityObjectByPointer(Token, DACL_SECURITY_INFORMATION, &NewSecurityDescriptor);

Exit:
    if (NewDacl)
    {
        ExFreePool(NewDacl);
    }

    if (SecurityDescriptor)
    {
        ObReleaseObjectSecurity(SecurityDescriptor, MemoryAllocated);
    }

    return Status;
}
PVOID
NTSYSAPI
RtlFindAceByType(
    _In_ PACL Acl,
    _In_ UCHAR AceType,
    _Out_opt_ PULONG Index
);
NTSYSAPI
NTSTATUS

RtlAddProcessTrustLabelAce(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ PSID ProcessTrustLabelSid,
    _In_ UCHAR AceType, // SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
    _In_ ACCESS_MASK AccessMask
);


NTSYSAPI
NTSTATUS

RtlSetSaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN SaclPresent,
    _In_opt_ PACL Sacl,
    _In_ BOOLEAN SaclDefaulted
);

NTSTATUS SepSetProcessTrustLabelAceForToken(PTOKEN Token)
{
    SECURITY_DESCRIPTOR Sd = { 0 };
    PSID TrustLevelSid; 
    NTSTATUS Status; 
    PISECURITY_DESCRIPTOR OldSd = NULL; 
    BOOLEAN MemoryAllocated = FALSE; 
    PACL TokenSacl;
    PSYSTEM_PROCESS_TRUST_LABEL_ACE TrustLabelAce;
    ULONG AceIndex; 
    ACL_REVISION_INFORMATION RevisionInfo;
    ACL_SIZE_INFORMATION AclSizeInfo; 
    PVOID Ace = NULL ; 
    ULONG AclSize; 
    PACL NewSacl = NULL; 

    if (Token == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RevisionInfo.AclRevision = ACL_REVISION2;
    AclSizeInfo.AclBytesInUse = sizeof(ACL);

    TrustLevelSid = Token->TrustLevelSid; 

    Status = ObGetObjectSecurity(Token, &OldSd, &MemoryAllocated);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (OldSd == NULL)
    {
        return Status; 
    }

    TokenSacl = RtlpSaclAddrSecurityDescriptor(OldSd);

    if (TokenSacl)
    {
        TrustLabelAce = RtlFindAceByType(TokenSacl, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, &AceIndex);

        if (TrustLevelSid == NULL)
        {
            if (TrustLabelAce == NULL)
            {
                goto Exit;
            }
        }
        else if (TrustLabelAce && RtlEqualSid(&(TrustLabelAce->SidStart), TrustLevelSid))
        {
            TrustLabelAce->Mask &= (READ_CONTROL | TOKEN_QUERY_SOURCE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE);
            goto Exit;
        }

        Status = RtlQueryInformationAcl(TokenSacl, &AclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }

        Status = RtlQueryInformationAcl(TokenSacl, &RevisionInfo, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);

        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }

        Status = RtlGetAce(TokenSacl, 0, &Ace);

        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }
    }

    AclSize = AclSizeInfo.AclBytesInUse + SeLengthSid(TrustLevelSid) + FIELD_OFFSET(SYSTEM_PROCESS_TRUST_LABEL_ACE, SidStart);


    NewSacl = ExAllocatePool2(POOL_FLAG_PAGED, AclSize, SEP_ACL_TAG);

    if (NewSacl == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    Status = RtlCreateAcl(NewSacl, AclSize, RevisionInfo.AclRevision);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (Ace != NULL)
    {
        Status = RtlAddAce(NewSacl, RevisionInfo.AclRevision, 0, Ace, AclSizeInfo.AclBytesInUse - sizeof(ACL));

        if (!NT_SUCCESS(Status))
        {
            goto Exit;
        }
    }

    Status = RtlAddProcessTrustLabelAce(NewSacl,
        ACL_REVISION2,
        0,
        TrustLevelSid,
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        (READ_CONTROL | TOKEN_QUERY_SOURCE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE));

    if (!NT_SUCCESS(Status))
    {
        goto Exit; 
    }

    Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);

    if (!NT_SUCCESS(Status))
    {
        goto Exit; 
    }

    Sd.Revision = SECURITY_DESCRIPTOR_REVISION;

    Status = RtlSetSaclSecurityDescriptor(&Sd, TRUE, NewSacl, FALSE);

    if (!NT_SUCCESS(Status))
    {
        goto Exit; 
    }
    
    RtlpPropagateControlBits(&Sd, OldSd, (SE_SACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT | SE_SACL_DEFAULTED));

    Status = ObSetSecurityObjectByPointer(Token,
        (ACCESS_FILTER_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION),
        &Sd);


Exit:
    if (NewSacl)
    {
        ExFreePool(NewSacl);
    }

    if (OldSd)
    {
        ObReleaseObjectSecurity(OldSd, MemoryAllocated);
    }

    return Status; 
}

NTSTATUS SepFinalizeTokenAcls(PTOKEN Token)
{
    NTSTATUS Status;

    Status = SepAppendAceToTokenObjectAcl(Token, TOKEN_QUERY, SeAliasAdminsSid);

    if (NT_SUCCESS(Status))
    {
        return SepSetProcessTrustLabelAceForToken(Token);
    }
    return Status;
}

NTSTATUS NTAPI NtCreateLowBoxToken(
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
    KPROCESSOR_MODE Mode;
    PTOKEN ExistingToken;
    OBJECT_HANDLE_INFORMATION ohi = { 0 , 0 };
    NTSTATUS Status;
    PISID CapturedPackageSid = NULL;
    PSID_AND_ATTRIBUTES CapturedCapabilities = NULL;
    ULONG CapturedCapabilitiesSize = 0;
    BOOLEAN bDuplicatedToken = FALSE;
    BOOLEAN bTokenLocked = FALSE;
    PTOKEN DuplicatedToken = NULL;
    HANDLE NewTokenHandle = 0;
    HANDLE* CapturedHandles = NULL;
    ULONG Index;
    ULONG SidIndex;
    BOOLEAN bLegit = FALSE;
    TOKEN_MANDATORY_POLICY MandtoryPolicy = { TOKEN_MANDATORY_POLICY_NO_WRITE_UP };
    PSID_AND_ATTRIBUTES TokenIntegrity;
    PISID IntegritySid;
    SEP_CACHED_HANDLES_ENTRY_DESCRIPTOR chEntryDescriptor = { 0 , 0 };

    APPCONTAINER_SID_TYPE AppContainerSidType;
    ACCESS_MASK GrantedAccess;

    Mode = ExGetPreviousMode();


    if (Mode)
    {
        __try
        {
            ProbeForWriteHandle(TokenHandle);

            ProbeForRead(Handles, sizeof(HANDLE) * HandleCount, sizeof(HANDLE));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }

    if (PackageSid == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //ensure HandleCount and Handles pointer are consistent
    //*(zero count requires NULL pointer and vice versa)

    if (HandleCount == 0)
    {
        if (Handles != NULL)
        {
            return STATUS_INVALID_PARAMETER_MIX;
        }
    }
    else
    {
        if (Handles == NULL)
        {
            return STATUS_INVALID_PARAMETER_MIX;
        }
    }

    ExistingToken = NULL;

    Status = ObReferenceObjectByHandle(ExistingTokenHandle, TOKEN_DUPLICATE, *SeTokenObjectType, Mode, &ExistingToken, &ohi);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = SeCaptureSid(PackageSid, Mode, NULL, 0, POOL_ZERO_ALLOCATION | PagedPool, TRUE, &CapturedPackageSid);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }


    // Verify caller's privilege for creating LowBox token - must be non-LowBox process or parent AppContainer

    Status = SepCheckCreateLowBox(CapturedPackageSid);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    // Impersonation token must be at SecurityImpersonation level or higher

    if (ExistingToken->TokenType != TokenPrimary && ExistingToken->ImpersonationLevel < SecurityImpersonation)
    {
        ObDereferenceObject(ExistingToken);
        return STATUS_BAD_IMPERSONATION_LEVEL;
    }

    GrantedAccess = ohi.GrantedAccess;

    if (DesiredAccess)
    {
        GrantedAccess = DesiredAccess;
    }


    // Capture capabilities and handles

    if (Capabilities)
    {
        Status = SeCaptureSidAndAttributesArray(Capabilities, CapabilityCount, Mode, NULL, 0, POOL_ZERO_ALLOCATION | PagedPool, TRUE, &CapturedCapabilities, &CapturedCapabilitiesSize);
    }

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }


    Status = SepCaptureHandles(HandleCount, Handles, &CapturedHandles);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    //check captured packaged sid

    if (RtlIsPackageSid(CapturedPackageSid) == FALSE)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (CapturedPackageSid->SubAuthorityCount != SECURITY_APP_PACKAGE_RID_COUNT && CapturedPackageSid->SubAuthorityCount != SECURITY_CHILD_PACKAGE_RID_COUNT)
    {
        Status = STATUS_INVALID_PACKAGE_SID_LENGTH;
        goto Exit;
    }


    //Check for duplicated SID

    for (Index = 0; Index < CapabilityCount; Index++)
    {
        if (RtlIsCapabilitySid(CapturedCapabilities[Index].Sid) == FALSE)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }


        for (SidIndex = 0; SidIndex < Index; SidIndex++)
        {
            if (RtlEqualSid(CapturedCapabilities[Index].Sid, CapturedCapabilities[SidIndex].Sid) == TRUE)
            {
                Status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }
        }
    }

    //AppSilo checking added Win11 24H2
    if (!SepCapabilitiesHasAppSiloBaseSID(CapabilityCount, CapturedCapabilities))
    {
        for (Index = 0; Index < CapabilityCount; Index++)
        {
            if (SepIsAppSiloCapability(CapturedCapabilities[Index].Sid))
            {
                Status = STATUS_INVALID_PARAMETER;
                goto Exit; 
            }
        }
    }
    //end


    Status = RtlGetAppContainerSidType(CapturedPackageSid, &AppContainerSidType);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    //Check for child app container sid creation


    if (AppContainerSidType == ChildAppContainerSidType)
    {
        Status = SepCheckCapabilities(ExistingToken, CapabilityCount, CapturedCapabilities, 0, &bLegit);

        if (bLegit == FALSE)
        {
            Status = STATUS_ACCESS_DENIED;
            goto Exit;
        }
    }

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = SepDuplicateToken(ExistingToken,
        ObjectAttributes,
        FALSE,
        TokenPrimary,
        SecurityAnonymous,
        Mode,
        FALSE,
        &DuplicatedToken);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    bDuplicatedToken = TRUE;

    Status = SeSetMandatoryPolicyToken(DuplicatedToken, &MandtoryPolicy);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    SepAcquireTokenWriteLock(DuplicatedToken);

    bTokenLocked = TRUE;

    TokenIntegrity = SepLocateTokenIntegrity(DuplicatedToken);

    if (TokenIntegrity == NULL)
    {
        Status = STATUS_INVALID_LABEL;
        goto Exit;
    }

    IntegritySid = TokenIntegrity->Sid;

    if (*RtlSubAuthorityCountSid(IntegritySid))
    {
        *RtlSubAuthoritySid(IntegritySid, *RtlSubAuthorityCountSid(IntegritySid) - 1) = MANDATORY_LEVEL_TO_MANDATORY_RID(MandatoryLevelLow);
    }

    DuplicatedToken->Privileges.Enabled &= ((1 << SE_CHANGE_NOTIFY_PRIVILEGE) | (1 << SE_UNDOCK_PRIVILEGE));
    DuplicatedToken->Privileges.EnabledByDefault &= ((1 << SE_CHANGE_NOTIFY_PRIVILEGE) | (1 <<SE_UNDOCK_PRIVILEGE));
    DuplicatedToken->Privileges.Present &= ((1 << SE_CHANGE_NOTIFY_PRIVILEGE) | (1 << SE_UNDOCK_PRIVILEGE));
    DuplicatedToken->TokenFlags &= ~TOKEN_NOT_LOW;
    DuplicatedToken->TokenFlags |= TOKEN_LOWBOX;

    Status = SepSetTokenCapabilities(DuplicatedToken, CapturedPackageSid, CapturedCapabilities, CapabilityCount);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = SepSetTokenLowboxNumber(DuplicatedToken, CapturedPackageSid);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    chEntryDescriptor.u1.PackageSid = CapturedPackageSid; 

    Status = SepSetTokenCachedHandles(DuplicatedToken, &chEntryDescriptor, HandleCount, CapturedHandles);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = SepSetTokenPackage(DuplicatedToken, CapturedPackageSid);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    Status = SepAppendAceToTokenDefaultDacl(DuplicatedToken, CapturedPackageSid);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    //Added 23H2

    if (SepSidInTokenSidHash(&DuplicatedToken->CapabilitiesHash, NULL, SePermissiveLearningModeCapabilitySid, FALSE, FALSE, TRUE))
    {
        // It's impossible to have learning mode capability in the duplicated token
        // without having SepLearningModeTokenCount (in 22H2 and below),
        // but we perform the check anyway

        if (KernelSymbols.SepLearningModeTokenCount)
            InterlockedAdd((LONG*)KernelSymbols.SepLearningModeTokenCount , 1);
        DuplicatedToken->TokenFlags |= TOKEN_PERMISSIVE_LEARNING_MODE;
    }
    else
    {
        DuplicatedToken->TokenFlags &= ~TOKEN_PERMISSIVE_LEARNING_MODE;

        if (SepSidInTokenSidHash(&DuplicatedToken->CapabilitiesHash, NULL, SeLearningModeLoggingCapabilitySid, FALSE , FALSE , TRUE))
        {
            // It's impossible to have learning mode capability in the duplicated token
            // without having SepLearningModeTokenCount (in 22H2 and below),
            // but we perform the check anyway

            if (KernelSymbols.SepLearningModeTokenCount)
                InterlockedAdd((LONG*)KernelSymbols.SepLearningModeTokenCount , 1);
            DuplicatedToken->TokenFlags |= TOKEN_LEARNING_MODE_LOGGING;
        }
    }
    //end

    SepReleaseTokenWriteLock(DuplicatedToken, TRUE);

    bTokenLocked = FALSE;

    //create token handle

    Status = ObInsertObject(DuplicatedToken, 0, GrantedAccess, 1, NULL, &NewTokenHandle);

    if (!NT_SUCCESS(Status))
    {
        bDuplicatedToken = FALSE;
        goto Exit; 
    }

    //Added 24H2

    Status = SepAppendAceToTokenObjectAcl(DuplicatedToken, TOKEN_ALL_ACCESS, CapturedPackageSid);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    //end

    SepFinalizeTokenAcls(DuplicatedToken);
    ObDereferenceObject(DuplicatedToken);
    bDuplicatedToken = FALSE;


Exit:
    if (bTokenLocked)
    {
        SepReleaseTokenWriteLock(DuplicatedToken, NT_SUCCESS(Status));
    }

    if (!NT_SUCCESS(Status))
    {
        if (bDuplicatedToken)
        {
            ObDereferenceObject(DuplicatedToken);
        }

        if (NewTokenHandle)
        {
            ObCloseHandle(NewTokenHandle, Mode);
        }
    }

    if (CapturedCapabilities)
    {
        SeReleaseLuidAndAttributesArray(CapturedCapabilities, Mode , TRUE );
    }

    if (CapturedPackageSid)
    {
        SeReleaseSid(CapturedPackageSid, Mode, TRUE);
    }

    if (ExistingToken)
    {
        ObDereferenceObject(ExistingToken);
    }

    if (CapturedHandles)
    {
        ExFreePool(CapturedHandles);
    }

    if (NT_SUCCESS(Status))
    {
        __try
        {
            *TokenHandle = NewTokenHandle;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }

    }

    return Status;
}



static SID_IDENTIFIER_AUTHORITY SepPackagesAuthority = { 0 , 0 , 0 , 0 , 0 , 16 };
static SID_IDENTIFIER_AUTHORITY SepNtAuthority = { 0,0,0,0,0,5 };
static SID_IDENTIFIER_AUTHORITY SepCreatorSidAuthority = { 0,0,0,0,0,3 };
PSID SeConstrainedImpersonationCapabilityGroupSid = NULL;

//learning mode names

UNICODE_STRING LeanringModeLoggingCapabilitySidName = RTL_CONSTANT_STRING(L"learningModeLogging");
UNICODE_STRING PermissiveLearningModeCapabilitySidName = RTL_CONSTANT_STRING(L"permissiveLearningMode");

UNICODE_STRING LpacCapabilitySidNames[] = {
    RTL_CONSTANT_STRING(L"lpacAppExperience"),
    RTL_CONSTANT_STRING(L"lpacCom"),
    RTL_CONSTANT_STRING(L"lpacCryptoServices"),
    RTL_CONSTANT_STRING(L"lpacIdentityServices"),
    RTL_CONSTANT_STRING(L"lpacInstrumentation"),
    RTL_CONSTANT_STRING(L"lpacEnterprisePolicyChangeNotifications"),
    RTL_CONSTANT_STRING(L"lpacMedia"),
    RTL_CONSTANT_STRING(L"lpacPnpNotifications"),
    RTL_CONSTANT_STRING(L"registryRead"),
    RTL_CONSTANT_STRING(L"lpacServicesManagement"),
    RTL_CONSTANT_STRING(L"lpacSessionManagement"),
    RTL_CONSTANT_STRING(L"lpacPrinting"),
    RTL_CONSTANT_STRING(L"lpacWebPlatform"),
    RTL_CONSTANT_STRING(L"lpacPayments"),
    RTL_CONSTANT_STRING(L"lpacClipboard"),
    RTL_CONSTANT_STRING(L"lpacIME"),
    RTL_CONSTANT_STRING(L"lpacPackageManagerOperation"),
    RTL_CONSTANT_STRING(L"lpacDeviceAccess")
};

NTSTATUS
NTSYSAPI
RtlDeriveCapabilitySidsFromName(
    _Inout_ PUNICODE_STRING UnicodeString,
    _Out_ PSID CapabilityGroupSid,
    _Out_ PSID CapabilitySid
);



VOID UninitKnownSIDs()
{
    ULONG i; 

    if (SeAppSiloSid)
    {
        ExFreePool(SeAppSiloSid);
        SeAppSiloSid = NULL;
    }
    if (SeAliasAdminsSid)
    {
        ExFreePool(SeAliasAdminsSid);
        SeAliasAdminsSid = NULL;
    }
    if (SePrincipalSelfSid)
    {
        ExFreePool(SePrincipalSelfSid);
        SePrincipalSelfSid = NULL;
    }
    if (SeOwnerRightsSid)
    {
        ExFreePool(SeOwnerRightsSid);
        SeOwnerRightsSid = NULL;
    }
    if (SeLearningModeLoggingCapabilitySid)
    {
        ExFreePool(SeLearningModeLoggingCapabilitySid);
        SeLearningModeLoggingCapabilitySid = NULL;
    }
    if (SePermissiveLearningModeCapabilitySid)
    {
        ExFreePool(SePermissiveLearningModeCapabilitySid);
        SePermissiveLearningModeCapabilitySid = NULL;
    }

    if (SeConstrainedImpersonationCapabilityGroupSid)
    {
        ExFreePool(SeConstrainedImpersonationCapabilityGroupSid);
        SeConstrainedImpersonationCapabilityGroupSid = NULL; 
    }

    for (i = 0; i < SE_LPAC_CAPABILITY_COUNT; i++)
    {
        if (*SeLpacCapabilitySids[i])
        {
            ExFreePool(*SeLpacCapabilitySids[i]);
            *(PSID*)SeLpacCapabilitySids[i] = NULL;
        }
    }

    return;

}
NTSTATUS InitKnownSIDs()
{
    NTSTATUS Status; 
    ULONG i; 

    //SeAppSiloSid
    SeAppSiloSid = ExAllocatePool2(POOL_FLAG_NON_PAGED/* | POOL_FLAG_RAISE_ON_FAILURE*/, RtlLengthRequiredSid(SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT), SEP_SID_TAG);

    if (SeAppSiloSid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    RtlInitializeSid(SeAppSiloSid, &SepPackagesAuthority, SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT);

    *RtlSubAuthoritySid(SeAppSiloSid, 0) = SECURITY_CAPABILITY_BASE_RID;
    *RtlSubAuthoritySid(SeAppSiloSid, 1) = SECURITY_CAPABILITY_APP_SILO_RID;

    //SeAliasAdminsSid
    SeAliasAdminsSid = ExAllocatePool2(POOL_FLAG_PAGED/* | POOL_FLAG_RAISE_ON_FAILURE*/, RtlLengthRequiredSid(2), SEP_SID_TAG);

    if (SeAliasAdminsSid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    RtlInitializeSid(SeAliasAdminsSid, &SepNtAuthority, 2);

    *RtlSubAuthoritySid(SeAliasAdminsSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(SeAliasAdminsSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

    //SePrincipalSelfSid
    SePrincipalSelfSid = ExAllocatePool2(POOL_FLAG_NON_PAGED /* | POOL_FLAG_RAISE_ON_FAILURE*/, RtlLengthRequiredSid(1), SEP_SID_TAG);

    if (SePrincipalSelfSid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    RtlInitializeSid(SePrincipalSelfSid, &SepNtAuthority, 1);

    *RtlSubAuthoritySid(SePrincipalSelfSid, 0) = SECURITY_PRINCIPAL_SELF_RID;


    //SeOwnerRightsSid
    SeOwnerRightsSid = ExAllocatePool2(POOL_FLAG_NON_PAGED/* | POOL_FLAG_RAISE_ON_FAILURE*/, RtlLengthRequiredSid(1), SEP_SID_TAG);

    if (SeOwnerRightsSid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    RtlInitializeSid(SeOwnerRightsSid, &SepCreatorSidAuthority, 1);

    *RtlSubAuthoritySid(SeOwnerRightsSid, 0) = SECURITY_CREATOR_OWNER_RIGHTS_RID;

    //Initialize the SeConstrainedImpersonationCapabilityGroupSid first 

    SeConstrainedImpersonationCapabilityGroupSid = ExAllocatePool2(POOL_FLAG_PAGED, RtlLengthRequiredSid(SECURITY_INSTALLER_GROUP_CAPABILITY_RID_COUNT), SEP_SID_TAG);

    if (SeConstrainedImpersonationCapabilityGroupSid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }
    
    //we don't need to initialze the group SID

    //SeLearningModeLoggingCapabilitySid
    SeLearningModeLoggingCapabilitySid = ExAllocatePool2(POOL_FLAG_PAGED/* | POOL_FLAG_RAISE_ON_FAILURE*/, RtlLengthRequiredSid(10), SEP_SID_TAG);

    if (SeLearningModeLoggingCapabilitySid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    Status = RtlDeriveCapabilitySidsFromName(&LeanringModeLoggingCapabilitySidName, SeConstrainedImpersonationCapabilityGroupSid, SeLearningModeLoggingCapabilitySid);

    if (!NT_SUCCESS(Status))
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    //SePermissiveLearningModeCapabilitySid
    SePermissiveLearningModeCapabilitySid = ExAllocatePool2(POOL_FLAG_PAGED/* | POOL_FLAG_RAISE_ON_FAILURE*/, RtlLengthRequiredSid(10), SEP_SID_TAG);

    if (SePermissiveLearningModeCapabilitySid == NULL)
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    Status = RtlDeriveCapabilitySidsFromName(&PermissiveLearningModeCapabilitySidName, SeConstrainedImpersonationCapabilityGroupSid, SePermissiveLearningModeCapabilitySid);

    if (!NT_SUCCESS(Status))
    {
        UninitKnownSIDs();
        return STATUS_NO_MEMORY;
    }

    for (i = 0; i < SE_LPAC_CAPABILITY_COUNT; i++)
    {
        *(PSID*)SeLpacCapabilitySids[i] = ExAllocatePool2(POOL_FLAG_PAGED, RtlLengthRequiredSid(10), SEP_SID_TAG);

        if (*SeLpacCapabilitySids[i] == NULL)
        {
            UninitKnownSIDs();
            return STATUS_NO_MEMORY;
        }

        Status = RtlDeriveCapabilitySidsFromName(&LpacCapabilitySidNames[i], SeConstrainedImpersonationCapabilityGroupSid, *SeLpacCapabilitySids[i]);

        if (!NT_SUCCESS(Status))
        {
            UninitKnownSIDs();
            return STATUS_NO_MEMORY;
        }
    }
    

    return STATUS_SUCCESS; 
}
UNICODE_STRING DirectoryName = RTL_CONSTANT_STRING(L"\\");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices");
OBJECT_ATTRIBUTES DirectoryOBA = RTL_CONSTANT_OBJECT_ATTRIBUTES(&DirectoryName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);
OBJECT_ATTRIBUTES SymlinkOBA = RTL_CONSTANT_OBJECT_ATTRIBUTES(&SymLinkName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

NTSTATUS InitKernelSymbols(PVOID Buffer , ULONG Length)
{
    NTSTATUS Status;
    HANDLE DirectoryHandle, SymbolicLinkHandle;
    PVOID Object;

    if (bSystemSymbolInitialized)
    {
        return STATUS_SUCCESS; 
    }

    if (Length < sizeof(SYSTEM_SYMBOLS_PARAMS))
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&KernelSymbols, Buffer, sizeof(SYSTEM_SYMBOLS_PARAMS));

    Status = ZwOpenDirectoryObject(&DirectoryHandle, DIRECTORY_QUERY, &DirectoryOBA);

    if (!NT_SUCCESS(Status))
    {
        return Status; 
    }

    Status = ObReferenceObjectByHandle(DirectoryHandle, 0, NULL, KernelMode, &Object, NULL);

    if (!NT_SUCCESS(Status))
    {
        ZwClose(DirectoryHandle);
        return Status;
    }

    ObpDirectoryObjectType = ObGetObjectType(Object);

    ObDereferenceObject(Object);

    ZwClose(DirectoryHandle);

    Status = ZwOpenSymbolicLinkObject(&SymbolicLinkHandle, SYMBOLIC_LINK_QUERY, &SymlinkOBA);

    if (!NT_SUCCESS(Status))
    {
        return Status; 
    }

    Status = ObReferenceObjectByHandle(SymbolicLinkHandle, 0, NULL, KernelMode, &Object, NULL);

    if (!NT_SUCCESS(Status))
    {
        ZwClose(SymbolicLinkHandle);
        return Status; 
    }

    ObpSymbolicLinkObjectType = ObGetObjectType(Object);

    ObDereferenceObject(Object);

    ZwClose(SymbolicLinkHandle);

    Status = InitKnownSIDs();

    if (!NT_SUCCESS(Status))
    {
        return Status; 
    }

    bSystemSymbolInitialized = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS IrpDispatch(PDEVICE_OBJECT DeviceObject, PIRP pIrp)
{
	PIO_STACK_LOCATION IrpStack;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG_PTR Information = 0;
    PLOWBOXTOKEN_PARAMS LowboxTokenParam;

 
	UNREFERENCED_PARAMETER(DeviceObject);

	IrpStack = IoGetCurrentIrpStackLocation(pIrp);


	if (IrpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NTCREATELOWBOXTOKEN)
		{
			if (IrpStack->Parameters.DeviceIoControl.InputBufferLength != sizeof(LOWBOXTOKEN_PARAMS))
			{
				Status = STATUS_INVALID_PARAMETER;
				goto cleanup; 
			}

            LowboxTokenParam = (PLOWBOXTOKEN_PARAMS)pIrp->AssociatedIrp.SystemBuffer;

            if (bSystemSymbolInitialized == FALSE)
            {
                Status = STATUS_NOT_IMPLEMENTED;
                goto cleanup;
            }

            Status = NtCreateLowBoxToken(LowboxTokenParam->TokenHandle,
                LowboxTokenParam->ExistingTokenHandle,
                LowboxTokenParam->DesiredAccess,
                LowboxTokenParam->ObjectAttributes,
                LowboxTokenParam->PackageSid,
                LowboxTokenParam->CapabilityCount,
                LowboxTokenParam->Capabilities,
                LowboxTokenParam->HandleCount,
                LowboxTokenParam->Handles);
		}
        else if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_SYSTEM_SYMBOLS)
        {
            Status = InitKernelSymbols(pIrp->AssociatedIrp.SystemBuffer, IrpStack->Parameters.DeviceIoControl.InputBufferLength);
        }
		else
		{
			Status = STATUS_NOT_IMPLEMENTED; 
		}
	}

cleanup:

	pIrp->IoStatus.Status = Status;
	pIrp->IoStatus.Information = Information;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);

    IoDeleteSymbolicLink(&DosDeviceName);

    UninitKnownSIDs();

    return;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING Registry)
{
	NTSTATUS Status;
	PDEVICE_OBJECT DeviceObject;
	int i;

	UNREFERENCED_PARAMETER(Registry);

	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &DeviceObject);

	if (NT_SUCCESS(Status) == FALSE)
	{
		return Status;
	}


	Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	if (NT_SUCCESS(Status) == FALSE)
	{
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = IrpDispatch;
	}

	DriverObject->DriverUnload = DriverUnload;


	return STATUS_SUCCESS;

}
