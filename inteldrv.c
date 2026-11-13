// language: C, file: inteldrv.c, target: Windows Kernel (WDM), x64
#include <ntifs.h>
#include <wdmsec.h>
#include <wdmguid.h>
#include <initguid.h>

#pragma comment(lib, "wdmsec.lib")

#define INTEL_DEVICE_NAME   L"\\Device\\IntelDrv"
#define INTEL_SYMLINK_NAME  L"\\DosDevices\\IntelDrv"
#define TARGET_IMAGE_NAME   L"r5apex.exe"

#define IOCTL_GET_BASE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define MAX_IOCTL_SIZE      (1 * 1024 * 1024)
#define USER_VA_LIMIT       0x00007FFFFFFFFFFFULL

typedef struct _MEMORY_REQUEST {
    ULONG   ProcessId;
    ULONG   _pad;
    ULONG64 Address;
    ULONG64 Size;
    ULONG64 Buffer;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

typedef struct _BASE_REQUEST {
    ULONG   ProcessId;
    ULONG   _pad;
    ULONG64 BaseOut;
} BASE_REQUEST, *PBASE_REQUEST;

static NTSTATUS ProbeUserBuffer(PVOID UserVa, SIZE_T Size, BOOLEAN ForWrite)
{
    if (!UserVa || Size == 0) return STATUS_INVALID_PARAMETER;
    ULONG_PTR va = (ULONG_PTR)UserVa;
    if (va + Size < va) return STATUS_INVALID_PARAMETER;
    if ((ULONG64)(va + Size) > USER_VA_LIMIT) return STATUS_INVALID_PARAMETER;

    __try {
        if (ForWrite) ProbeForWrite(UserVa, Size, 1);
        else          ProbeForRead(UserVa, Size, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static NTSTATUS CopyUserToBounce(PVOID UserVa, PVOID Bounce, SIZE_T Size, KPROCESSOR_MODE AccessMode)
{
    PMDL mdl = IoAllocateMdl(UserVa, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        MmProbeAndLockPages(mdl, AccessMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status)) {
        PVOID mapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
        if (mapped) {
            RtlCopyMemory(Bounce, mapped, Size);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        MmUnlockPages(mdl);
    }
    IoFreeMdl(mdl);
    return status;
}

static NTSTATUS CopyBounceToUser(PVOID Bounce, PVOID UserVa, SIZE_T Size, KPROCESSOR_MODE AccessMode)
{
    PMDL mdl = IoAllocateMdl(UserVa, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        MmProbeAndLockPages(mdl, AccessMode, IoWriteAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status)) {
        PVOID mapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
        if (mapped) {
            RtlCopyMemory(mapped, Bounce, Size);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        MmUnlockPages(mdl);
    }
    IoFreeMdl(mdl);
    return status;
}

static NTSTATUS CrossProcessCopy(ULONG ProcessId, ULONG64 Address, PVOID KernelBuf, SIZE_T Size, BOOLEAN IsWrite)
{
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T copied = 0;
    if (IsWrite) {
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), KernelBuf,
                                     Process, (PVOID)(ULONG_PTR)Address,
                                     Size, KernelMode, &copied);
    } else {
        status = MmCopyVirtualMemory(Process, (PVOID)(ULONG_PTR)Address,
                                     PsGetCurrentProcess(), KernelBuf,
                                     Size, KernelMode, &copied);
    }

    ObDereferenceObject(Process);

    if (NT_SUCCESS(status) && copied != Size) return STATUS_PARTIAL_COPY;
    return status;
}

static NTSTATUS GetMainImageBase(ULONG ProcessId, PULONG64 BaseOut)
{
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status)) return status;

    PVOID base = PsGetProcessSectionBaseAddress(Process);
    ObDereferenceObject(Process);

    if (!base) return STATUS_NOT_FOUND;
    *BaseOut = (ULONG64)(ULONG_PTR)base;
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) goto complete;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;

    if (!sysBuf) { status = STATUS_INVALID_PARAMETER; goto complete; }

    switch (code) {
    case IOCTL_GET_BASE: {
        if (inLen < sizeof(BASE_REQUEST) || outLen < sizeof(BASE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        PBASE_REQUEST req = (PBASE_REQUEST)sysBuf;
        status = GetMainImageBase(req->ProcessId, &req->BaseOut);
        if (NT_SUCCESS(status)) info = sizeof(BASE_REQUEST);
        break;
    }

    case IOCTL_READ_MEMORY:
    case IOCTL_WRITE_MEMORY: {
        if (inLen < sizeof(MEMORY_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PMEMORY_REQUEST req = (PMEMORY_REQUEST)sysBuf;
        if (req->Size == 0 || req->Size > MAX_IOCTL_SIZE || req->Buffer == 0) {
            status = STATUS_INVALID_PARAMETER; break;
        }

        BOOLEAN isWrite = (code == IOCTL_WRITE_MEMORY);

        status = ProbeUserBuffer((PVOID)(ULONG_PTR)req->Buffer, (SIZE_T)req->Size, !isWrite);
        if (!NT_SUCCESS(status)) break;

        PVOID bounce = ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)req->Size, 'ltnI');
        if (!bounce) { status = STATUS_INSUFFICIENT_RESOURCES; break; }

        if (isWrite) {
            status = CopyUserToBounce((PVOID)(ULONG_PTR)req->Buffer, bounce,
                                      (SIZE_T)req->Size, Irp->RequestorMode);
            if (NT_SUCCESS(status))
                status = CrossProcessCopy(req->ProcessId, req->Address, bounce,
                                          (SIZE_T)req->Size, TRUE);
        } else {
            status = CrossProcessCopy(req->ProcessId, req->Address, bounce,
                                      (SIZE_T)req->Size, FALSE);
            if (NT_SUCCESS(status))
                status = CopyBounceToUser(bounce, (PVOID)(ULONG_PTR)req->Buffer,
                                          (SIZE_T)req->Size, Irp->RequestorMode);
        }

        ExFreePoolWithTag(bounce, 'ltnI');
        if (NT_SUCCESS(status)) info = (ULONG)req->Size;
        break;
    }

    default: break;
    }

complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void DispatchUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, INTEL_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (DriverObject->DeviceObject) IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName, symlinkName;
    RtlInitUnicodeString(&deviceName, INTEL_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, INTEL_SYMLINK_NAME);

    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT device = NULL;

    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
        (LPCGUID)&GUID_DEVCLASS_UNKNOWN, &device);
    if (!NT_SUCCESS(status)) return status;

    device->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }

    device->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                         = DispatchUnload;

    return STATUS_SUCCESS;
}
