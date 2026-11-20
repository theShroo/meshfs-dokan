/*
  meshfs-dokan layout check: prints the offsets and sizes of the driver's
  structures as MSVC lays them out from Dokany's own sys/public.h (vendored
  here unmodified). sweep.sh diffs this against `cargo run --example
  layout_dump`, which prints the same names from src/proto.rs.

  Copyright (C) 2026 Harland Consulting. LGPL-3.0-or-later (COPYING.LESSER).
*/
#include <windows.h>
#include <winternl.h> /* UNICODE_STRING */
#include <stddef.h>
#include <stdio.h>
#include "public.h"
#include "../../include/meshfs_dokan.h" /* its size checks, under MSVC */

#define O(T, f, name) printf("%s %u\n", name, (unsigned)offsetof(T, f))
#define S(T, name) printf("%s %u\n", name, (unsigned)sizeof(T))

int main(void) {
  printf("FSCTL_GET_VERSION %u\n", (unsigned)FSCTL_GET_VERSION);
  printf("FSCTL_EVENT_RELEASE %u\n", (unsigned)FSCTL_EVENT_RELEASE);
  printf("FSCTL_EVENT_START %u\n", (unsigned)FSCTL_EVENT_START);
  printf("FSCTL_EVENT_WRITE %u\n", (unsigned)FSCTL_EVENT_WRITE);
  printf("FSCTL_RESET_TIMEOUT %u\n", (unsigned)FSCTL_RESET_TIMEOUT);
  printf("FSCTL_GET_ACCESS_TOKEN %u\n", (unsigned)FSCTL_GET_ACCESS_TOKEN);
  printf("FSCTL_ACTIVATE_KEEPALIVE %u\n", (unsigned)FSCTL_ACTIVATE_KEEPALIVE);
  printf("FSCTL_NOTIFY_PATH %u\n", (unsigned)FSCTL_NOTIFY_PATH);
  printf("FSCTL_GET_VOLUME_METRICS %u\n", (unsigned)FSCTL_GET_VOLUME_METRICS);
  printf("FSCTL_EVENT_PROCESS_N_PULL %u\n", (unsigned)FSCTL_EVENT_PROCESS_N_PULL);
  printf("DOKAN_DRIVER_VERSION %u\n", (unsigned)DOKAN_DRIVER_VERSION);

  S(EVENT_CONTEXT, "EVENT_CONTEXT.size");
  O(EVENT_CONTEXT, Length, "EVENT_CONTEXT.Length");
  O(EVENT_CONTEXT, MountId, "EVENT_CONTEXT.MountId");
  O(EVENT_CONTEXT, SerialNumber, "EVENT_CONTEXT.SerialNumber");
  O(EVENT_CONTEXT, ProcessId, "EVENT_CONTEXT.ProcessId");
  O(EVENT_CONTEXT, MajorFunction, "EVENT_CONTEXT.MajorFunction");
  O(EVENT_CONTEXT, MinorFunction, "EVENT_CONTEXT.MinorFunction");
  O(EVENT_CONTEXT, Flags, "EVENT_CONTEXT.Flags");
  O(EVENT_CONTEXT, FileFlags, "EVENT_CONTEXT.FileFlags");
  O(EVENT_CONTEXT, Context, "EVENT_CONTEXT.Context");
  O(EVENT_CONTEXT, Operation, "EVENT_CONTEXT.Operation");
  O(EVENT_CONTEXT, Operation.Directory.FileInformationClass, "Directory.FileInformationClass");
  O(EVENT_CONTEXT, Operation.Directory.FileIndex, "Directory.FileIndex");
  O(EVENT_CONTEXT, Operation.Directory.BufferLength, "Directory.BufferLength");
  O(EVENT_CONTEXT, Operation.Directory.DirectoryNameLength, "Directory.DirectoryNameLength");
  O(EVENT_CONTEXT, Operation.Directory.SearchPatternLength, "Directory.SearchPatternLength");
  O(EVENT_CONTEXT, Operation.Directory.SearchPatternOffset, "Directory.SearchPatternOffset");
  O(EVENT_CONTEXT, Operation.Directory.DirectoryName, "Directory.DirectoryName");
  O(EVENT_CONTEXT, Operation.Directory.SearchPatternBase, "Directory.SearchPatternBase");
  O(EVENT_CONTEXT, Operation.Read.ByteOffset, "Read.ByteOffset");
  O(EVENT_CONTEXT, Operation.Read.BufferLength, "Read.BufferLength");
  O(EVENT_CONTEXT, Operation.Read.FileNameLength, "Read.FileNameLength");
  O(EVENT_CONTEXT, Operation.Read.FileName, "Read.FileName");
  O(EVENT_CONTEXT, Operation.Write.ByteOffset, "Write.ByteOffset");
  O(EVENT_CONTEXT, Operation.Write.BufferLength, "Write.BufferLength");
  O(EVENT_CONTEXT, Operation.Write.BufferOffset, "Write.BufferOffset");
  O(EVENT_CONTEXT, Operation.Write.RequestLength, "Write.RequestLength");
  O(EVENT_CONTEXT, Operation.Write.FileNameLength, "Write.FileNameLength");
  O(EVENT_CONTEXT, Operation.Write.FileName, "Write.FileName");
  O(EVENT_CONTEXT, Operation.File.FileInformationClass, "File.FileInformationClass");
  O(EVENT_CONTEXT, Operation.File.BufferLength, "File.BufferLength");
  O(EVENT_CONTEXT, Operation.File.FileNameLength, "File.FileNameLength");
  O(EVENT_CONTEXT, Operation.File.FileName, "File.FileName");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.SecurityEvaluated, "Create.SecurityEvaluated");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.Flags, "Create.AccessStateFlags");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.RemainingDesiredAccess, "Create.RemainingDesiredAccess");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.PreviouslyGrantedAccess, "Create.PreviouslyGrantedAccess");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.OriginalDesiredAccess, "Create.OriginalDesiredAccess");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.SecurityDescriptorOffset, "Create.SecurityDescriptorOffset");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.UnicodeStringObjectNameOffset, "Create.ObjectNameOffset");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.AccessState.UnicodeStringObjectTypeOffset, "Create.ObjectTypeOffset");
  O(EVENT_CONTEXT, Operation.Create.SecurityContext.DesiredAccess, "Create.DesiredAccess");
  O(EVENT_CONTEXT, Operation.Create.FileAttributes, "Create.FileAttributes");
  O(EVENT_CONTEXT, Operation.Create.CreateOptions, "Create.CreateOptions");
  O(EVENT_CONTEXT, Operation.Create.ShareAccess, "Create.ShareAccess");
  O(EVENT_CONTEXT, Operation.Create.FileNameLength, "Create.FileNameLength");
  O(EVENT_CONTEXT, Operation.Create.FileNameOffset, "Create.FileNameOffset");
  O(EVENT_CONTEXT, Operation.Cleanup.FileNameLength, "Cleanup.FileNameLength");
  O(EVENT_CONTEXT, Operation.Cleanup.FileName, "Cleanup.FileName");
  O(EVENT_CONTEXT, Operation.Close.FileName, "Close.FileName");
  O(EVENT_CONTEXT, Operation.Flush.FileName, "Flush.FileName");
  O(EVENT_CONTEXT, Operation.SetFile.FileInformationClass, "SetFile.FileInformationClass");
  O(EVENT_CONTEXT, Operation.SetFile.BufferLength, "SetFile.BufferLength");
  O(EVENT_CONTEXT, Operation.SetFile.BufferOffset, "SetFile.BufferOffset");
  O(EVENT_CONTEXT, Operation.SetFile.FileNameLength, "SetFile.FileNameLength");
  O(EVENT_CONTEXT, Operation.SetFile.FileName, "SetFile.FileName");
  O(EVENT_CONTEXT, Operation.Lock.ByteOffset, "Lock.ByteOffset");
  O(EVENT_CONTEXT, Operation.Lock.Length, "Lock.Length");
  O(EVENT_CONTEXT, Operation.Lock.Key, "Lock.Key");
  O(EVENT_CONTEXT, Operation.Lock.FileNameLength, "Lock.FileNameLength");
  O(EVENT_CONTEXT, Operation.Lock.FileName, "Lock.FileName");
  O(EVENT_CONTEXT, Operation.Volume.FsInformationClass, "Volume.FsInformationClass");
  O(EVENT_CONTEXT, Operation.Volume.BufferLength, "Volume.BufferLength");
  O(EVENT_CONTEXT, Operation.Security.SecurityInformation, "Security.SecurityInformation");
  O(EVENT_CONTEXT, Operation.Security.BufferLength, "Security.BufferLength");
  O(EVENT_CONTEXT, Operation.Security.FileNameLength, "Security.FileNameLength");
  O(EVENT_CONTEXT, Operation.Security.FileName, "Security.FileName");
  O(EVENT_CONTEXT, Operation.SetSecurity.SecurityInformation, "SetSecurity.SecurityInformation");
  O(EVENT_CONTEXT, Operation.SetSecurity.BufferLength, "SetSecurity.BufferLength");
  O(EVENT_CONTEXT, Operation.SetSecurity.BufferOffset, "SetSecurity.BufferOffset");
  O(EVENT_CONTEXT, Operation.SetSecurity.FileNameLength, "SetSecurity.FileNameLength");
  O(EVENT_CONTEXT, Operation.SetSecurity.FileName, "SetSecurity.FileName");

  S(EVENT_INFORMATION, "EVENT_INFORMATION.size");
  O(EVENT_INFORMATION, SerialNumber, "EVENT_INFORMATION.SerialNumber");
  O(EVENT_INFORMATION, Status, "EVENT_INFORMATION.Status");
  O(EVENT_INFORMATION, Flags, "EVENT_INFORMATION.Flags");
  O(EVENT_INFORMATION, Operation.Directory.Index, "EVENT_INFORMATION.Directory.Index");
  O(EVENT_INFORMATION, Operation.Create.Flags, "EVENT_INFORMATION.Create.Flags");
  O(EVENT_INFORMATION, Operation.Create.Information, "EVENT_INFORMATION.Create.Information");
  O(EVENT_INFORMATION, Operation.Read.CurrentByteOffset, "EVENT_INFORMATION.Read.CurrentByteOffset");
  O(EVENT_INFORMATION, Operation.Delete.DeletePending, "EVENT_INFORMATION.Delete.DeletePending");
  O(EVENT_INFORMATION, Operation.ResetTimeout.Timeout, "EVENT_INFORMATION.ResetTimeout.Timeout");
  O(EVENT_INFORMATION, Operation.AccessToken.Handle, "EVENT_INFORMATION.AccessToken.Handle");
  O(EVENT_INFORMATION, Context, "EVENT_INFORMATION.Context");
  O(EVENT_INFORMATION, BufferLength, "EVENT_INFORMATION.BufferLength");
  O(EVENT_INFORMATION, PullEventTimeoutMs, "EVENT_INFORMATION.PullEventTimeoutMs");
  O(EVENT_INFORMATION, Buffer, "EVENT_INFORMATION.Buffer");

  S(EVENT_START, "EVENT_START.size");
  O(EVENT_START, DeviceType, "EVENT_START.DeviceType");
  O(EVENT_START, Flags, "EVENT_START.Flags");
  O(EVENT_START, MountPoint, "EVENT_START.MountPoint");
  O(EVENT_START, UNCName, "EVENT_START.UNCName");
  O(EVENT_START, IrpTimeout, "EVENT_START.IrpTimeout");
  O(EVENT_START, FcbGarbageCollectionIntervalMs, "EVENT_START.FcbGarbageCollectionIntervalMs");
  O(EVENT_START, VolumeSecurityDescriptorLength, "EVENT_START.VolumeSecurityDescriptorLength");
  O(EVENT_START, VolumeSecurityDescriptor, "EVENT_START.VolumeSecurityDescriptor");

  S(EVENT_DRIVER_INFO, "EVENT_DRIVER_INFO.size");
  O(EVENT_DRIVER_INFO, Status, "EVENT_DRIVER_INFO.Status");
  O(EVENT_DRIVER_INFO, Flags, "EVENT_DRIVER_INFO.Flags");
  O(EVENT_DRIVER_INFO, DeviceNumber, "EVENT_DRIVER_INFO.DeviceNumber");
  O(EVENT_DRIVER_INFO, MountId, "EVENT_DRIVER_INFO.MountId");
  O(EVENT_DRIVER_INFO, DeviceName, "EVENT_DRIVER_INFO.DeviceName");
  O(EVENT_DRIVER_INFO, ActualDriveLetter, "EVENT_DRIVER_INFO.ActualDriveLetter");

  S(DOKAN_NOTIFY_PATH_INTERMEDIATE, "NOTIFY_PATH.size");
  O(DOKAN_NOTIFY_PATH_INTERMEDIATE, Action, "NOTIFY_PATH.Action");
  O(DOKAN_NOTIFY_PATH_INTERMEDIATE, Length, "NOTIFY_PATH.Length");
  O(DOKAN_NOTIFY_PATH_INTERMEDIATE, Buffer, "NOTIFY_PATH.Buffer");
  S(DOKAN_UNICODE_STRING_INTERMEDIATE, "USTR.size");
  O(DOKAN_UNICODE_STRING_INTERMEDIATE, MaximumLength, "USTR.MaximumLength");
  O(DOKAN_UNICODE_STRING_INTERMEDIATE, Buffer, "USTR.Buffer");
  O(DOKAN_RENAME_INFORMATION, FileNameLength, "RENAME.FileNameLength");
  O(DOKAN_RENAME_INFORMATION, FileName, "RENAME.FileName");
  return 0;
}
