/*
  meshfs_dokan.h: the C ABI of meshfs_dokan.dll, version 1.1.

  meshfs-dokan is a port of Dokany 2.3.1's user-mode protocol (dokan2.dll) to
  Rust. It talks to the unmodified dokan2.sys driver and hands every request
  to the host through the MdHostV1 callback table. It holds no file-system
  logic, cache or security policy.

  Copyright (C) 2026 Harland Consulting. Ported from Dokany (see NOTICE).
  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by the
  Free Software Foundation; either version 3 of the License, or (at your
  option) any later version. See COPYING.LESSER.

  Conventions
  - Strings are UTF-16: a pointer and a length in code units, no terminator,
    valid only during the call that hands them over (except where a
    NUL-terminated string is stated). Paths are relative to the volume
    ("\dir\file"), normalised as dokan2.dll's CheckFileName.
  - Times are FILETIME values (100 ns since 1601) as uint64_t.
  - Statuses are NTSTATUS values.
  - x64 only; natural alignment; sizes are asserted at the end.

  Threading and lifetimes
  - Callbacks run on the library's pull threads, several at once. They must
    not block on slow work: queue it and return STATUS_PENDING, then answer
    with md_reply from any thread. md_reply may be called even before the
    callback returns STATUS_PENDING (the reply is held until it does).
  - md_reply never waits on the driver: the reply is copied and sent by the
    library's own threads, so a host may call it from its event loop. (The
    driver completes the IRP inside the reply call, and that completion can
    wait for the answer to another request — a cleanup's, on the file's FCB
    lock or its oplocks.)
  - A pending request answered after the driver timed it out (IrpTimeout,
    15 s minimum, 5 min maximum) is dropped by the driver; md_reset_timeout
    extends one request.
  - No exception or panic may cross the boundary in either direction.
  - After md_unmount returns MD_OK the instance is gone: no further calls,
    and no md_reply for its requests.
*/
#ifndef MESHFS_DOKAN_H
#define MESHFS_DOKAN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MD_ABI_MAJOR 1
#define MD_ABI_MINOR 1
#define MD_ABI_VERSION ((MD_ABI_MAJOR << 16) | MD_ABI_MINOR)

typedef int32_t MdNtStatus;
typedef struct MdInstance MdInstance;

/* md_mount results */
#define MD_OK 0
#define MD_ERR_ARGS 1            /* null pointer, short table/options, unknown major */
#define MD_ERR_DRIVER_MISSING 2  /* \\.\Dokan_2 cannot be opened */
#define MD_ERR_DRIVER_VERSION 3  /* the driver's protocol is not one we speak */
#define MD_ERR_MOUNT 4           /* the driver refused the mount */
#define MD_ERR_START 5           /* volume device or pull threads failed */
#define MD_ERR_INTERNAL 6        /* a panic was caught */
#define MD_ERR_THREAD 7          /* md_unmount called on a pull thread */

/* MdMountOptions.flags */
#define MD_MOUNT_CASE_SENSITIVE (1u << 0)
#define MD_MOUNT_MOUNT_MANAGER (1u << 1)
/* Visible only in the mounting logon session. From an ELEVATED process the
   drive lands in the elevated logon's namespace and the user's unelevated
   Explorer does not see it (measured); global (flag off) is the default. */
#define MD_MOUNT_CURRENT_SESSION (1u << 2)
#define MD_MOUNT_WRITE_PROTECT (1u << 3)
#define MD_MOUNT_REMOVABLE (1u << 4)
#define MD_MOUNT_NETWORK (1u << 5)
#define MD_MOUNT_ENABLE_NETWORK_UNMOUNT (1u << 6)
/* ABI 1.1: named streams (alternate data streams). The library declares
   FILE_NAMED_STREAMS, asks the driver for stream names, splits every
   request's name into MdRequest.path + MdRequest.stream, and answers
   FileStreamInformation from find_streams. Needs a 1.1 table with
   find_streams (else MD_ERR_ARGS). Which streams exist is the host's. */
#define MD_MOUNT_NAMED_STREAMS (1u << 7)

/* MdRequest.file_flags */
#define MD_FILE_PAGING_IO (1u << 0)
#define MD_FILE_SYNCHRONOUS_IO (1u << 1)
#define MD_FILE_NOCACHE (1u << 2)            /* how the request came in only */
#define MD_FILE_WRITE_TO_END_OF_FILE (1u << 3)
#define MD_FILE_DELETE_ON_CLOSE (1u << 4)    /* on cleanup: delete now */
#define MD_FILE_DIRECTORY (1u << 5)

/* MdCreateRequest.flags */
#define MD_CREATE_OPEN_TARGET_DIRECTORY (1u << 0) /* open path's parent dir; target = full name */
#define MD_CREATE_CASE_SENSITIVE (1u << 1)

/* MdCreateReply.flags */
#define MD_CREATE_IS_DIRECTORY (1u << 0)
#define MD_CREATE_TARGET_MISSING (1u << 1)

/* MdSetInfoRequest.kind */
#define MD_SET_BASIC 1
#define MD_SET_ALLOCATION 2
#define MD_SET_END_OF_FILE 3
#define MD_SET_VALID_DATA_LENGTH 4
#define MD_SET_DISPOSITION 5
#define MD_SET_RENAME 6

typedef struct MdRequest {
  uint64_t request_id;  /* the driver's serial: for md_reply, md_reset_timeout, md_requester_token */
  uint64_t context;     /* the host's per-open context (0 on create) */
  uint32_t process_id;  /* the requesting process */
  uint32_t irp_flags;   /* IO_STACK_LOCATION.Flags (SL_*) */
  uint32_t file_flags;  /* MD_FILE_* */
  uint8_t major_function;
  uint8_t minor_function;
  uint16_t _reserved;
  const uint16_t *path;
  uint32_t path_len;
  uint32_t _reserved2;
  /* ABI 1.1, with MD_MOUNT_NAMED_STREAMS: the stream the request names,
     without its ":$DATA" type ("f:Zone.Identifier:$DATA" -> "Zone.Identifier"),
     and path is the file's name alone. 0 units for the unnamed data stream
     ("f" and "f::$DATA"). A type other than $DATA stays on. NULL/0
     otherwise. A 1.0 host never reads these fields. */
  const uint16_t *stream;
  uint32_t stream_len;
  uint32_t _reserved3;
} MdRequest;

typedef struct MdCreateRequest {
  uint32_t desired_access;
  uint32_t file_attributes;
  uint32_t share_access;
  uint32_t disposition;     /* FILE_SUPERSEDE .. FILE_OVERWRITE_IF */
  uint32_t create_options;  /* low 24 bits of CreateOptions */
  uint32_t flags;           /* MD_CREATE_* */
  uint32_t original_desired_access;
  uint32_t remaining_desired_access;
  uint32_t previously_granted_access;
  uint32_t access_state_flags;
  const uint8_t *security_descriptor; /* new object's, self-relative; may be NULL */
  uint32_t security_descriptor_len;   /* an upper bound: use the descriptor's own length */
  uint32_t target_len;
  const uint16_t *target;             /* with MD_CREATE_OPEN_TARGET_DIRECTORY */
} MdCreateRequest;

typedef struct MdCreateReply {
  uint64_t context;  /* returned on every later request of this open */
  uint32_t flags;    /* MD_CREATE_IS_DIRECTORY, MD_CREATE_TARGET_MISSING */
  uint32_t _reserved;
} MdCreateReply;

typedef struct MdFileInfo {
  uint32_t attributes;
  uint32_t number_of_links;
  uint64_t creation_time;
  uint64_t last_access_time;
  uint64_t last_write_time;
  uint64_t change_time;      /* 0: same as last_write_time */
  uint64_t file_size;
  uint64_t allocation_size;  /* 0: file_size rounded up to the allocation unit */
  uint64_t file_index;
  uint32_t volume_serial;
  uint32_t _reserved;
} MdFileInfo;

typedef struct MdSetInfoRequest {
  uint32_t kind;          /* MD_SET_* */
  uint32_t info_class;    /* the raw FILE_INFORMATION_CLASS */
  uint32_t attributes;    /* MD_SET_BASIC; 0 = unchanged */
  uint32_t _reserved;
  int64_t creation_time;  /* MD_SET_BASIC: 0 = unchanged, -1 = stop updating */
  int64_t last_access_time;
  int64_t last_write_time;
  int64_t change_time;
  int64_t size;           /* ALLOCATION / END_OF_FILE / VALID_DATA_LENGTH */
  uint8_t delete_;        /* MD_SET_DISPOSITION */
  uint8_t replace_if_exists; /* MD_SET_RENAME */
  uint16_t _pad;
  uint32_t ex_flags;      /* ...InformationEx flags */
  const uint16_t *new_name; /* MD_SET_RENAME, relative to the volume */
  uint32_t new_name_len;
  uint32_t _reserved2;
} MdSetInfoRequest;

typedef struct MdFindEntry {
  const uint16_t *name;
  uint32_t name_len;
  uint32_t attributes;
  uint64_t creation_time;
  uint64_t last_access_time;
  uint64_t last_write_time;
  uint64_t change_time;      /* 0: same as last_write_time */
  uint64_t file_size;
  uint64_t allocation_size;  /* 0: rounded up from file_size */
  uint64_t file_id;
} MdFindEntry;

/* ABI 1.1: one stream of a file, for find_streams. name is the bare stream
   name (0 units = the unnamed data stream); the library writes the NTFS
   form ("::$DATA", ":name:$DATA"). */
typedef struct MdStreamEntry {
  const uint16_t *name;
  uint32_t name_len;
  uint32_t _reserved;
  uint64_t size;
  uint64_t allocation_size;  /* 0: rounded up from size */
} MdStreamEntry;

/* Called by the host during find_streams, once per stream; returns 0, or
   STATUS_BUFFER_OVERFLOW once the caller's buffer is full (stop). */
typedef int32_t (*MdStreamFill)(void *fill_ctx, const MdStreamEntry *entry);

/* Called by the host during find_files, once per entry; returns 0. */
typedef int32_t (*MdFindFill)(void *fill_ctx, const MdFindEntry *entry);

typedef struct MdVolumeInfo {
  uint64_t total_bytes;
  uint64_t free_bytes;
  uint64_t available_bytes;  /* free to the caller */
  uint32_t serial;
  uint32_t max_component_length;
  uint32_t fs_flags;         /* FILE_CASE_SENSITIVE_SEARCH ... */
  uint32_t label_len;
  uint32_t fs_name_len;
  uint32_t _reserved;
  uint16_t label[32];
  uint16_t fs_name[16];
} MdVolumeInfo;

/* One deferred answer; the fields for the request's operation are read:
   create: create. read: data/data_len (the bytes). write: bytes (written).
   query_info: file_info. find_files: entries/entry_count (all entries; the
   library filters, pages and keeps them per open). query_volume: volume
   (or status STATUS_NOT_IMPLEMENTED for dokan2.dll's defaults).
   query_security: data/data_len (the descriptor), bytes (length needed,
   0 = data_len). Others: status only. */
typedef struct MdReply {
  uint64_t request_id;
  MdNtStatus status;
  uint32_t bytes;
  const uint8_t *data;
  uint32_t data_len;
  uint32_t entry_count;
  const MdCreateReply *create;
  const MdFileInfo *file_info;
  const MdVolumeInfo *volume;
  const MdFindEntry *entries;
} MdReply;

typedef struct MdMountOptions {
  uint32_t size;                 /* sizeof(MdMountOptions) */
  uint32_t flags;                /* MD_MOUNT_* */
  const uint16_t *mount_point;   /* NUL-terminated: "T:", "T:\" or an empty NTFS folder */
  const uint16_t *unc_name;      /* NUL-terminated, MD_MOUNT_NETWORK only; else NULL */
  uint32_t irp_timeout_ms;       /* 0 = 15 s; the driver clamps to 15 s .. 5 min */
  uint32_t fcb_gc_interval_ms;   /* 0 = 2000 */
  uint32_t pull_threads;         /* 0 = processor count clamped to 2..16 */
  uint32_t sector_size;          /* 0 = 512 */
  uint32_t allocation_unit_size; /* 0 = 512 */
  uint32_t volume_security_descriptor_len; /* <= 16 KiB */
  const uint8_t *volume_security_descriptor; /* self-relative, or NULL */
} MdMountOptions;

/* The host's callback table. A NULL entry answers STATUS_NOT_IMPLEMENTED,
   except: cleanup (STATUS_SUCCESS), flush (STATUS_SUCCESS), query_volume
   (dokan2.dll's defaults), close/mounted/unmounted (nothing).
   Every status-returning callback may return STATUS_PENDING. */
typedef struct MdHostV1 {
  uint32_t size;     /* sizeof(MdHostV1) as built; later entries are NULL */
  uint32_t version;  /* MD_ABI_VERSION the host was built against */
  void *user;
  /* Status per dokan2.dll: STATUS_OBJECT_NAME_COLLISION with FILE_OPEN_IF,
     FILE_OVERWRITE_IF or FILE_SUPERSEDE means "opened an existing file" and
     succeeds. The library computes the Information value. Access checks are
     the host's: the library makes none. */
  MdNtStatus (*create)(void *user, const MdRequest *req, const MdCreateRequest *p, MdCreateReply *out);
  /* Always answered STATUS_SUCCESS. MD_FILE_DELETE_ON_CLOSE: delete now. */
  MdNtStatus (*cleanup)(void *user, const MdRequest *req);
  /* No reply. Comes after the kernel completed every IRP of the open; free
     the context here. */
  void (*close)(void *user, const MdRequest *req);
  /* buffer is the reply buffer itself: write up to length bytes, set
     *out_bytes. 0 bytes with STATUS_SUCCESS answers STATUS_END_OF_FILE. */
  MdNtStatus (*read)(void *user, const MdRequest *req, int64_t offset, uint32_t length, uint8_t *buffer,
                     uint32_t *out_bytes);
  /* data is valid during the call only (copy it before pending). */
  MdNtStatus (*write)(void *user, const MdRequest *req, int64_t offset, const uint8_t *data, uint32_t length,
                      uint32_t *out_bytes);
  MdNtStatus (*flush)(void *user, const MdRequest *req);
  MdNtStatus (*query_info)(void *user, const MdRequest *req, uint32_t info_class, MdFileInfo *out);
  MdNtStatus (*set_info)(void *user, const MdRequest *req, const MdSetInfoRequest *p);
  /* Called when a listing must be (re)made; fill every entry (pattern is a
     hint: the library applies it). */
  MdNtStatus (*find_files)(void *user, const MdRequest *req, const uint16_t *pattern, uint32_t pattern_len,
                           MdFindFill fill, void *fill_ctx);
  MdNtStatus (*query_volume)(void *user, const MdRequest *req, MdVolumeInfo *out);
  /* Write the self-relative descriptor into buffer, set *out_needed; if it
     does not fit, return STATUS_BUFFER_OVERFLOW with *out_needed set. */
  MdNtStatus (*query_security)(void *user, const MdRequest *req, uint32_t security_information, uint8_t *buffer,
                               uint32_t buffer_len, uint32_t *out_needed);
  MdNtStatus (*set_security)(void *user, const MdRequest *req, uint32_t security_information,
                             const uint8_t *descriptor, uint32_t descriptor_len);
  /* device_name is the volume device (\Volume{...}); the host may open
     \\.\<device_name> to tighten its security descriptor (see design 4.1.6). */
  void (*mounted)(void *user, const uint16_t *mount_point, uint32_t mount_point_len, const uint16_t *device_name,
                  uint32_t device_name_len);
  /* Once per mount: from the last pull thread when the driver ends the mount,
     or from md_unmount. */
  void (*unmounted)(void *user);
  /* ABI 1.1 (present when size covers it): the streams of the open req
     names, for FileStreamInformation with MD_MOUNT_NAMED_STREAMS. Fill
     every stream, the unnamed data stream included. Synchronous: it must
     not return STATUS_PENDING. */
  MdNtStatus (*find_streams)(void *user, const MdRequest *req, MdStreamFill fill, void *fill_ctx);
} MdHostV1;

uint32_t md_abi_version(void);
/* FSCTL_GET_VERSION; 0 if the driver is not installed or not running. */
uint32_t md_driver_version(void);
/* 1 if this library speaks driver protocol `version` (0x190 = Dokany 2.3.1). */
int32_t md_driver_version_supported(uint32_t version);
int32_t md_mount(const MdMountOptions *options, const MdHostV1 *host, MdInstance **out);
/* Unmounts, joins the pull threads, calls unmounted (once), frees. */
int32_t md_unmount(MdInstance *instance);
/* Answers pending requests, one driver call each. Returns how many were
   accepted (unknown or already answered ids are skipped). */
uint32_t md_reply(MdInstance *instance, const MdReply *replies, uint32_t count);
/* FSCTL_NOTIFY_PATH; path relative to the volume. 0 or a Win32 error. */
uint32_t md_notify_path(MdInstance *instance, const uint16_t *path, uint32_t path_len, uint32_t filter,
                        uint32_t action);
/* FSCTL_GET_ACCESS_TOKEN for a create being handled (in its callback or
   pending). The caller closes the handle. -1 on failure. Note: the driver
   hands this to any process that can open the volume device (design 4.1.6). */
intptr_t md_requester_token(MdInstance *instance, uint64_t request_id);
/* A documented no-op for driver protocol 0x190: the driver never caches
   handle I/O (every ReadFile/WriteFile reaches the host) and nothing a reply
   or mount flag can set controls the one cached path, pages of memory-mapped
   views and image sections. Returns STATUS_SUCCESS. */
MdNtStatus md_set_no_cache(MdInstance *instance, uint64_t request_id);
/* FSCTL_RESET_TIMEOUT: timeout_ms more for a pending request (0 = the
   mount's IrpTimeout). 0 or a Win32 error. */
uint32_t md_reset_timeout(MdInstance *instance, uint64_t request_id, uint32_t timeout_ms);

#if defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
typedef char md_check_request[sizeof(MdRequest) == 64 ? 1 : -1];
typedef char md_check_stream_entry[sizeof(MdStreamEntry) == 32 ? 1 : -1];
typedef char md_check_create_request[sizeof(MdCreateRequest) == 64 ? 1 : -1];
typedef char md_check_create_reply[sizeof(MdCreateReply) == 16 ? 1 : -1];
typedef char md_check_file_info[sizeof(MdFileInfo) == 72 ? 1 : -1];
typedef char md_check_set_info[sizeof(MdSetInfoRequest) == 80 ? 1 : -1];
typedef char md_check_find_entry[sizeof(MdFindEntry) == 72 ? 1 : -1];
typedef char md_check_volume[sizeof(MdVolumeInfo) == 144 ? 1 : -1];
typedef char md_check_reply[sizeof(MdReply) == 64 ? 1 : -1];
typedef char md_check_options[sizeof(MdMountOptions) == 56 ? 1 : -1];
typedef char md_check_host[sizeof(MdHostV1) == 136 ? 1 : -1];
#endif

#ifdef __cplusplus
}
#endif
#endif /* MESHFS_DOKAN_H */
