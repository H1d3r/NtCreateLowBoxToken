#pragma once
#include "ntddk.h"
#include <ntifs.h>

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\NtCreateLowboxToken");
UNICODE_STRING DosDeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\NtCreateLowboxToken");

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

typedef NTSTATUS(*PSEP_DUPLICATE_TOKEN)(
    PVOID ExistingToken,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    KPROCESSOR_MODE RequestorMode,
    BOOLEAN SkipNonInheritableSecurityAttributes,
    PVOID* DuplicateToken
    );
typedef NTSTATUS(*PSEP_APPEND_ACE_TO_TOKEN_OBJECT_ACL)(PVOID Token, ACCESS_MASK Access, PSID Sid);
typedef NTSTATUS(*PSEP_SET_PROCESS_TRUST_LABEL_ACE_FOR_TOKEN)(PVOID Token);

typedef struct SYSTEM_SYMBOLS_PARAMS {
    PVOID LowboxSessionMapLock;
    PVOID g_SessionLowboxArray;
    PVOID g_SessionLowboxMap;
    PVOID SepLearningModeTokenCount;
    PVOID g_SepSidMapping;
    PVOID SepTokenCapabilitySidSharingEnabled;
     PSEP_DUPLICATE_TOKEN SepDuplicateToken;
}SYSTEM_SYMBOLS_PARAMS , *PSYSTEM_SYMBOLS_PARAMS;




FORCEINLINE
VOID
ProbeForReadSmallStructure(
    IN PVOID Address,
    IN SIZE_T Size,
    IN ULONG Alignment
)

{
    if ((Size == 0) || (Size >= 0x10000)) {

        ProbeForRead(Address, Size, Alignment);

    }
    else {
        if (((ULONG_PTR)Address & (Alignment - 1)) != 0) {
            ExRaiseDatatypeMisalignment();
        }

        if ((PUCHAR)Address >= (UCHAR* const)MM_USER_PROBE_ADDRESS) {
            Address = (UCHAR* const)MM_USER_PROBE_ADDRESS;
        }

        _ReadWriteBarrier();
        *(volatile UCHAR*)Address;
    }
}


FORCEINLINE
LARGE_INTEGER
ProbeAndReadLargeInteger(LARGE_INTEGER* Address)
{
    if (Address >= (LARGE_INTEGER* const)MM_USER_PROBE_ADDRESS) {
        Address = (LARGE_INTEGER* const)MM_USER_PROBE_ADDRESS;
    }

    _ReadWriteBarrier();
    return *((volatile LARGE_INTEGER*)Address);
}

FORCEINLINE
VOID
ProbeForWriteHandle( PHANDLE Address)

{
    if (Address >= (HANDLE* const)MM_USER_PROBE_ADDRESS) {
        Address = (HANDLE* const)MM_USER_PROBE_ADDRESS;
    }

    *((volatile HANDLE*)Address) = *Address;
    return;
}


FORCEINLINE
VOID
ProbeForWriteSmallStructure(
    IN PVOID Address,
    IN SIZE_T Size,
    IN ULONG Alignment)
{
    if ((Size == 0) || (Size >= 0x1000)) {

        ProbeForWrite(Address, Size, Alignment);

    }
    else {
        if (((ULONG_PTR)(Address) & (Alignment - 1)) != 0) {
            ExRaiseDatatypeMisalignment();
        }

        if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
            Address = (UCHAR* const)MM_USER_PROBE_ADDRESS;
        }

        ((volatile UCHAR*)(Address))[0] = ((volatile UCHAR*)(Address))[0];
        ((volatile UCHAR*)(Address))[Size - 1] = ((volatile UCHAR*)(Address))[Size - 1];

    }
}

FORCEINLINE
VOID
ProbeAndReadStructureWorker(
     PVOID Destination,
    CONST VOID* Source,
   SIZE_T Size
)

{
    if (Source >= (VOID* const)MM_USER_PROBE_ADDRESS) {
        Source = (VOID* const)MM_USER_PROBE_ADDRESS;
    }

    memcpy(Destination, Source, Size);
    _ReadWriteBarrier();
    return;
}

#define ProbeAndReadStructureEx(Dst, Src, STRUCTURE)                         \
    ProbeAndReadStructureWorker(&(Dst), Src, sizeof(STRUCTURE))



FORCEINLINE
UCHAR
ProbeAndReadUchar(UCHAR* Address)

{
    if (Address >= (UCHAR* const)MM_USER_PROBE_ADDRESS) {
        Address = (UCHAR* const)MM_USER_PROBE_ADDRESS;
    }

    _ReadWriteBarrier();
    return *((volatile UCHAR*)Address);
}



#define SepAcquireTokenReadLock(T)  KeEnterCriticalRegion();          \
                                    ExAcquireResourceSharedLite((T)->TokenLock, TRUE)

#define SepAcquireTokenWriteLock(T) KeEnterCriticalRegion();          \
                                    ExAcquireResourceExclusiveLite((T)->TokenLock, TRUE); \
                                    KeMemoryBarrier();

#define SepReleaseTokenReadLock(T)  ExReleaseResourceLite((T)->TokenLock);  \
                                    KeLeaveCriticalRegion()

#define SepReleaseTokenWriteLock(T,M)                                    \
    {                                                                    \
      if ((M)) {                                                         \
          ZwAllocateLocallyUniqueId( &((PTOKEN)(T))->ModifiedId  );      \
      }                                                                  \
      KeMemoryBarrier();                                                 \
      SepReleaseTokenReadLock( T );                                      \
    }

//
// Currently define Flags for "OBJECT" ACE types.
//

#define ACE_OBJECT_TYPE_PRESENT           0x1
#define ACE_INHERITED_OBJECT_TYPE_PRESENT 0x2

#define IsAllowedAceType(Ace) ( \
   (((PACE_HEADER)(Ace))->AceType == ACCESS_ALLOWED_ACE_TYPE                 || \
   ((PACE_HEADER)(Ace))->AceType == ACCESS_DENIED_ACE_TYPE                  || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_AUDIT_ACE_TYPE                   || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_ALARM_ACE_TYPE                   || \
   ((PACE_HEADER)(Ace))->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE        || \
   ((PACE_HEADER)(Ace))->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE         || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_AUDIT_CALLBACK_ACE_TYPE          || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_ALARM_CALLBACK_ACE_TYPE          || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE         || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE     || \
   ((PACE_HEADER)(Ace))->AceType == SYSTEM_ACCESS_FILTER_ACE_TYPE)           \
)

#define IsCompoundAceType(Ace) (                                           \
    (((PACE_HEADER)(Ace))->AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE))

#define IsObjectAceType(Ace) (                                              \
    (((PACE_HEADER)(Ace))->AceType >= ACCESS_MIN_MS_OBJECT_ACE_TYPE) && \
    (((PACE_HEADER)(Ace))->AceType <= ACCESS_MAX_MS_OBJECT_ACE_TYPE)    \
    )

#define IsCallbackObjectAceType(Ace) (                                            \
    (((PACE_HEADER)(Ace))->AceType >= ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) && \
    (((PACE_HEADER)(Ace))->AceType <= ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)     \
    )

#define IsSytstemCallbackObjectAceType(Ace) (                                            \
    (((PACE_HEADER)(Ace))->AceType >= SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE) && \
    (((PACE_HEADER)(Ace))->AceType <= SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE)     \
    )
#define RtlObjectAceObjectTypePresent( Ace ) \
     ((((PKNOWN_OBJECT_ACE)(Ace))->Flags & ACE_OBJECT_TYPE_PRESENT) != 0 )
#define RtlObjectAceInheritedObjectTypePresent( Ace ) \
     ((((PKNOWN_OBJECT_ACE)(Ace))->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0 )

#define RtlObjectAceSid( Ace ) \
    ((PSID)(((PUCHAR)&(((PKNOWN_OBJECT_ACE)(Ace))->SidStart)) + \
     (RtlObjectAceObjectTypePresent(Ace) ? sizeof(GUID) : 0 ) + \
     (RtlObjectAceInheritedObjectTypePresent(Ace) ? sizeof(GUID) : 0 )))


#define FirstAce(Acl) ((PVOID)((PUCHAR)(Acl) + sizeof(ACL)))
#define NextAce(Ace) ((PVOID)((PUCHAR)(Ace) + ((PACE_HEADER)(Ace))->AceSize))

#define SID_HASH_ULONG(s)             ((((PISID)s)->SubAuthority[((PISID)s)->SubAuthorityCount - 1]))
#define AUTHZ_SID_HASH_BYTE(s)        ((UCHAR)(((PISID)s)->SubAuthority[((PISID)s)->SubAuthorityCount - 1]))
#define AUTHZ_SID_HASH_HIGH 16
#define AUTHZ_SID_HASH_LOOKUP(table, byte) (((table)[(byte) & 0xf]) & ((table)[AUTHZ_SID_HASH_HIGH + (((byte) & 0xf0) >> 4)]))
#define AUTHZI_SID_HASH_ENTRY_NUM_BITS (8*sizeof(SID_HASH_ENTRY))

#define RtlLengthRequiredSidCount(Count) (8 + (4 * Count))

#define LongAlignSize(Size) (((ULONG)(Size) + 3) & -4)

const UCHAR SidHashByteToIndexLookupTable[] = {
    0x09, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x07, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00
};



#define RtlpSaclAddrSecurityDescriptor( SD )                                   \
           ( (!((SD)->Control & SE_SACL_PRESENT) ) ?                           \
             (PACL)NULL :                                                      \
               (  ((SD)->Control & SE_SELF_RELATIVE) ?                         \
                   (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Sacl == 0) ? ((PACL) NULL) :            \
                           (PACL)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Sacl) \
                   ) :                                                         \
                   (PACL)((SD)->Sacl)                                          \
               )                                                               \
           )


#define RtlpDaclAddrSecurityDescriptor( SD )                                   \
           ( (!((SD)->Control & SE_DACL_PRESENT) ) ?                           \
             (PACL)NULL :                                                      \
               (  ((SD)->Control & SE_SELF_RELATIVE) ?                         \
                   (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Dacl == 0) ? ((PACL) NULL) :            \
                           (PACL)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Dacl) \
                   ) :                                                         \
                   (PACL)((SD)->Dacl)                                          \
               )                                                               \
           )

#define ValidAclRevision(Acl) ((Acl)->AclRevision >= MIN_ACL_REVISION && \
                               (Acl)->AclRevision <= MAX_ACL_REVISION )

//
//  Macro to copy the state of the passed bits from the old security
//  descriptor (OldSD) into the Control field of the new one (NewSD)
//

#define RtlpPropagateControlBits( NewSD, OldSD, Bits )                             \
            ( NewSD )->Control |=                     \
            (                                                                  \
            ( OldSD )->Control & ( Bits )             \
            )

#define SEP_MAX_GROUP_COUNT 4096


#define SEP_SID_AND_ATTRIBUTES_TAG          'aSeS'
#define SEP_SECURITY_DESCRIPTOR_TAG         'dSeS'
#define SEP_TOKEN_DYNAMIC_PART_TAG          'dTeS'
#define SEP_SID_TAG                         'iSeS'
#define SEP_OBJECT_NAME_INFORMATION_TAG     'nOeS'
#define SEP_SECURITY_ATTRIBUTES_TAG         'tAeS'
#define SEP_SID_SHARING_TAG                 'sSeS'
#define SEP_LOWBOX_SESSION_TAG              'sLeS'
#define RTL_PRIVATE_BUFFER_TAG              'bPtR'
#define SEP_HANDLES_CAPTURE_TAG             'cHeS'
#define SEP_ACL_TAG                         'cAeS'

typedef enum _APPCONTAINER_SID_TYPE
{
    NotAppContainerSidType,
    ChildAppContainerSidType,
    ParentAppContainerSidType,
    InvalidAppContainerSidType,
    MaxAppContainerSidType
} APPCONTAINER_SID_TYPE, * PAPPCONTAINER_SID_TYPE;

typedef struct _SEP_TOKEN_PRIVILEGES {
    ULONGLONG Present;
    ULONGLONG Enabled;
    ULONGLONG EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;

typedef struct _SEP_AUDIT_POLICY {
    TOKEN_AUDIT_POLICY AdtTokenPolicy;
    UCHAR PolicySetStatus;
} SEP_AUDIT_POLICY, * PSEP_AUDIT_POLICY;

typedef struct _OB_HANDLE_REVOCATION_BLOCK {
    LIST_ENTRY RevocationInfos;
    EX_PUSH_LOCK Lock;
    EX_RUNDOWN_REF Rundown;
} OB_HANDLE_REVOCATION_BLOCK, * POB_HANDLE_REVOCATION_BLOCK;

typedef struct _SEP_CACHED_HANDLES_TABLE {
    EX_PUSH_LOCK Lock;                    // +0x000
    PRTL_DYNAMIC_HASH_TABLE HashTable;    // +0x008
} SEP_CACHED_HANDLES_TABLE, * PSEP_CACHED_HANDLES_TABLE;

typedef struct _SEP_LOGON_SESSION_REFERENCES {
    struct _SEP_LOGON_SESSION_REFERENCES* Next;
    LUID LogonId;
    LUID BuddyLogonId;
    LONGLONG ReferenceCount;
    ULONG Flags;
    PVOID pDeviceMap;
    PVOID Token;
    UNICODE_STRING AccountName;
    UNICODE_STRING AuthorityName;
    SEP_CACHED_HANDLES_TABLE CachedHandlesTable;
    EX_PUSH_LOCK SharedDataLock;
    PVOID SharedClaimAttributes;
    PVOID SharedSidValues;
    OB_HANDLE_REVOCATION_BLOCK RevocationBlock;
    PVOID ServerSilo;
    LUID SiblingAuthId;
    LIST_ENTRY TokenList;
} SEP_LOGON_SESSION_REFERENCES, * PSEP_LOGON_SESSION_REFERENCES;

typedef struct _TOKEN {
    TOKEN_SOURCE TokenSource;                     // 0x000
    LUID TokenId;                                // 0x010
    LUID AuthenticationId;                       // 0x018  
    LUID ParentTokenId;                         // 0x020
    LARGE_INTEGER ExpirationTime;                // 0x028
    PVOID TokenLock;                            // 0x030
    LUID ModifiedId;                            // 0x038
    SEP_TOKEN_PRIVILEGES Privileges;             // 0x040
    SEP_AUDIT_POLICY AuditPolicy;               // 0x058
    ULONG SessionId;                            // 0x078
    ULONG UserAndGroupCount;                    // 0x07c
    ULONG RestrictedSidCount;                   // 0x080
    ULONG VariableLength;                       // 0x084
    ULONG DynamicCharged;                       // 0x088
    ULONG DynamicAvailable;                     // 0x08c
    ULONG DefaultOwnerIndex;                    // 0x090
    PSID_AND_ATTRIBUTES UserAndGroups;          // 0x098
    PSID_AND_ATTRIBUTES RestrictedSids;         // 0x0a0
    PSID PrimaryGroup;                          // 0x0a8
    PVOID DynamicPart;                          // 0x0b0
    PACL DefaultDacl;                           // 0x0b8
    TOKEN_TYPE TokenType;                       // 0x0c0
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; // 0x0c4
    ULONG TokenFlags;                           // 0x0c8
    UCHAR TokenInUse;                           // 0x0cc
    ULONG IntegrityLevelIndex;                  // 0x0d0
    ULONG MandatoryPolicy;                      // 0x0d4
    PSEP_LOGON_SESSION_REFERENCES LogonSession; // 0x0d8
    LUID OriginatingLogonSession;               // 0x0e0
    SID_AND_ATTRIBUTES_HASH SidHash;            // 0x0e8
    SID_AND_ATTRIBUTES_HASH RestrictedSidHash;  // 0x1f8
    PVOID pSecurityAttributes;                  // 0x308
    PSID Package;                              // 0x310
    PSID_AND_ATTRIBUTES Capabilities;           // 0x318
    ULONG CapabilityCount;                      // 0x320
    SID_AND_ATTRIBUTES_HASH CapabilitiesHash;   // 0x328
    PVOID LowboxNumberEntry;                    // 0x438
    PVOID LowboxHandlesEntry;                   // 0x440
    PVOID pClaimAttributes;                     // 0x448
    PSID TrustLevelSid;                        // 0x450
    PVOID TrustLinkedToken;                    // 0x458
    PSID IntegrityLevelSidValue;               // 0x460
    PVOID TokenSidValues;                      // 0x468
    PVOID IndexEntry;                          // 0x470
    PVOID DiagnosticInfo;                      // 0x478
    PVOID BnoIsolationHandlesEntry;            // 0x480
    PVOID SessionObject;                       // 0x488
    ULONGLONG VariablePart;                    // 0x490
} TOKEN, * PTOKEN;

//
// Group attributes
//

#define SE_GROUP_MANDATORY                 (0x00000001L)
#define SE_GROUP_ENABLED_BY_DEFAULT        (0x00000002L)
#define SE_GROUP_ENABLED                   (0x00000004L)
#define SE_GROUP_OWNER                     (0x00000008L)
#define SE_GROUP_USE_FOR_DENY_ONLY         (0x00000010L)
#define SE_GROUP_INTEGRITY                 (0x00000020L)
#define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
#define SE_GROUP_LOGON_ID                  (0xC0000000L)
#define SE_GROUP_RESOURCE                  (0x20000000L)

#define SE_GROUP_VALID_ATTRIBUTES          (SE_GROUP_MANDATORY          | \
                                            SE_GROUP_ENABLED_BY_DEFAULT | \
                                            SE_GROUP_ENABLED            | \
                                            SE_GROUP_OWNER              | \
                                            SE_GROUP_USE_FOR_DENY_ONLY  | \
                                            SE_GROUP_LOGON_ID           | \
                                            SE_GROUP_RESOURCE           | \
                                            SE_GROUP_INTEGRITY          | \
                                            SE_GROUP_INTEGRITY_ENABLED)

#define SE_MIN_WELL_KNOWN_PRIVILEGE         (2L)
#define SE_CREATE_TOKEN_PRIVILEGE           (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     (3L)
#define SE_LOCK_MEMORY_PRIVILEGE            (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE         (5L)
#define SE_UNSOLICITED_INPUT_PRIVILEGE      (6L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE        (6L)
#define SE_TCB_PRIVILEGE                    (7L)
#define SE_SECURITY_PRIVILEGE               (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE         (9L)
#define SE_LOAD_DRIVER_PRIVILEGE            (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE         (11L)
#define SE_SYSTEMTIME_PRIVILEGE             (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE      (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE        (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE       (16L)
#define SE_BACKUP_PRIVILEGE                 (17L)
#define SE_RESTORE_PRIVILEGE                (18L)
#define SE_SHUTDOWN_PRIVILEGE               (19L)
#define SE_DEBUG_PRIVILEGE                  (20L)
#define SE_AUDIT_PRIVILEGE                  (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE          (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        (24L)
#define SE_UNDOCK_PRIVILEGE                 (25L)
#define SE_SYNC_AGENT_PRIVILEGE             (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE      (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE          (28L)
#define SE_IMPERSONATE_PRIVILEGE            (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE          (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE                (32L)
#define SE_INC_WORKING_SET_PRIVILEGE        (33L)
#define SE_TIME_ZONE_PRIVILEGE              (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   (35L)

//
// Structure representing the mapping for lowbox numbers in the Windows kernel.
//
typedef struct _SEP_LOWBOX_NUMBER_MAPPING {
    EX_PUSH_LOCK Lock;                // +0x000: Synchronization primitive for accessing the structure.
    RTL_BITMAP Bitmap;                // +0x008: Bitmap used to track allocated or available lowbox numbers.
    PRTL_DYNAMIC_HASH_TABLE HashTable; // +0x018: Pointer to a dynamic hash table storing lowbox-related data.
    UCHAR Active;                     // +0x020: Indicates whether the mapping is active (non-zero) or inactive (zero).
} SEP_LOWBOX_NUMBER_MAPPING, * PSEP_LOWBOX_NUMBER_MAPPING;

//
// Structure representing an entry in the lowbox number mapping.
//
typedef struct _SEP_LOWBOX_NUMBER_ENTRY {
    RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry; // +0x000: Hash table entry for storing this structure in a dynamic hash table.
    LONG64 ReferenceCount;                   // +0x018: Reference count for this entry.
    PVOID PackageSid;                       // +0x020: Pointer to the SID (Security Identifier) associated with the lowbox.
    ULONG LowboxNumber;                    // +0x028: The lowbox number assigned to this entry.
    PVOID AtomTable;                        // +0x030: Pointer to an atom table for storing additional metadata.
} SEP_LOWBOX_NUMBER_ENTRY, * PSEP_LOWBOX_NUMBER_ENTRY;

//
// Structure representing a session lowbox map.
//
typedef struct _SESSION_LOWBOX_MAP {
    LIST_ENTRY ListEntry;               // +0x000: Doubly-linked list entry for linking this structure in a list.
    UINT32 SessionId;                   // +0x010: The session ID associated with this lowbox map.
    UINT32 Padding;                     // +0x014: Padding to align the next member to an 8-byte boundary.
    SEP_LOWBOX_NUMBER_MAPPING LowboxMap; // +0x018: The lowbox number mapping for this session.
} SESSION_LOWBOX_MAP, * PSESSION_LOWBOX_MAP;



typedef enum _SEP_CACHED_HANDLES_ENTRY_TYPE {
    SepCachedHandlesEntryLowbox = 0,
    SepCachedHandlesEntryBnoIsolation = 1
} SEP_CACHED_HANDLES_ENTRY_TYPE, * PSEP_CACHED_HANDLES_ENTRY_TYPE;

typedef struct _SEP_CACHED_HANDLES_ENTRY_DESCRIPTOR {
    SEP_CACHED_HANDLES_ENTRY_TYPE DescriptorType;  // +0x000
    union {
        PSID PackageSid;                           // +0x008
        UNICODE_STRING IsolationPrefix;            // +0x008
    }u1;
} SEP_CACHED_HANDLES_ENTRY_DESCRIPTOR, * PSEP_CACHED_HANDLES_ENTRY_DESCRIPTOR;

typedef struct _SEP_CACHED_HANDLES_ENTRY {
    RTL_DYNAMIC_HASH_TABLE_ENTRY HashEntry;       // +0x000
    LONG64 ReferenceCount;                        // +0x018
    SEP_CACHED_HANDLES_ENTRY_DESCRIPTOR EntryDescriptor;  // +0x020
    ULONG HandleCount;                            // +0x038
    PVOID** Handles;                             // +0x040
} SEP_CACHED_HANDLES_ENTRY, * PSEP_CACHED_HANDLES_ENTRY;

//wrk-v1.2
typedef struct _KNOWN_COMPOUND_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    USHORT CompoundAceType;
    USHORT Reserved;
    ULONG SidStart;
} KNOWN_COMPOUND_ACE, * PKNOWN_COMPOUND_ACE;

typedef struct _KNOWN_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG Flags;
    // GUID ObjectType;             // Optionally present
    // GUID InheritedObjectType;    // Optionally present
    ULONG SidStart;
} KNOWN_OBJECT_ACE, * PKNOWN_OBJECT_ACE;

typedef enum _ACL_INFORMATION_CLASS {
    AclRevisionInformation = 1,
    AclSizeInformation
} ACL_INFORMATION_CLASS;

typedef struct _ACL_REVISION_INFORMATION {
    ULONG AclRevision;
} ACL_REVISION_INFORMATION;
typedef ACL_REVISION_INFORMATION* PACL_REVISION_INFORMATION;

typedef struct _ACL_SIZE_INFORMATION {
    ULONG AceCount;
    ULONG AclBytesInUse;
    ULONG AclBytesFree;
} ACL_SIZE_INFORMATION;
typedef ACL_SIZE_INFORMATION* PACL_SIZE_INFORMATION;

#define MAX_OBJECT_PATH 256

typedef struct _ALLOWED_CACHED_DIRECTORY {
    UNICODE_STRING DirectoryName;
    BOOLEAN bCheckName; 
}ALLOWED_CACHED_DIRECTORY, *PALLOWED_CACHED_DIRECTORY;

typedef struct _OBJECT_HEADER_NAME_INFO {
    PVOID Directory; //POBJECT_DIRECTORY
    UNICODE_STRING Name;
    LONG ReferenceCount;
    ULONG Reserved;
} OBJECT_HEADER_NAME_INFO, * POBJECT_HEADER_NAME_INFO;

typedef struct _OBJECT_HEADER {
    // +0x000 PointerCount
    volatile LONG_PTR PointerCount;

    // +0x008 HandleCount / NextToFree (union)
    union {
        volatile LONG_PTR HandleCount;
        struct _OBJECT_HEADER* NextToFree;  // Void pointer
    };

    // +0x010 Lock
    EX_PUSH_LOCK Lock;

    // +0x018 TypeIndex
    UCHAR TypeIndex;

    // +0x019 TraceFlags / DbgRefTrace / DbgTracePermanent (bitfields)
    union {
        UCHAR TraceFlags;
        struct {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };

    // +0x01A InfoMask
    UCHAR InfoMask;

    // +0x01B Flags / bitfields
    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };

    // +0x01C Reserved
    ULONG Reserved;

    // +0x020 ObjectCreateInfo / QuotaBlockCharged (union)
    union {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;
        VOID* QuotaBlockCharged;
    };

    // +0x028 SecurityDescriptor
    VOID* SecurityDescriptor;

    // +0x030 Body
    QUAD Body;

} OBJECT_HEADER, * POBJECT_HEADER;

typedef struct _KNOWN_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} KNOWN_ACE, * PKNOWN_ACE;