// meshfs-dokan: the information classes' layouts checked against the Windows
// SDK metadata (windows-sys). Windows only; the driver's own structures are
// checked against public.h by sweep.sh (tests/c/layout.c).
// Copyright (C) 2026 Harland Consulting. LGPL-3.0-or-later (COPYING.LESSER).

#![cfg(windows)]

use core::mem::{offset_of, size_of};
use meshfs_dokan::marshal::{dir, info};
use meshfs_dokan::proto::*;
use windows_sys::Wdk::Storage::FileSystem as F;
use windows_sys::Wdk::System::SystemServices as S;
use windows_sys::Win32::Storage::FileSystem as W;

#[test]
fn directory_classes() {
    macro_rules! check {
        ($class:expr, $t:ty) => {
            assert_eq!(dir::layout($class), (size_of::<$t>(), offset_of!($t, FileName)), stringify!($t));
        };
    }
    check!(FILE_DIRECTORY_INFORMATION, F::FILE_DIRECTORY_INFORMATION);
    check!(FILE_FULL_DIRECTORY_INFORMATION, F::FILE_FULL_DIR_INFORMATION);
    check!(FILE_ID_FULL_DIRECTORY_INFORMATION, F::FILE_ID_FULL_DIR_INFORMATION);
    check!(FILE_NAMES_INFORMATION, F::FILE_NAMES_INFORMATION);
    check!(FILE_BOTH_DIRECTORY_INFORMATION, F::FILE_BOTH_DIR_INFORMATION);
    check!(FILE_ID_BOTH_DIRECTORY_INFORMATION, F::FILE_ID_BOTH_DIR_INFORMATION);
    check!(FILE_ID_EXTD_DIRECTORY_INFORMATION, W::FILE_ID_EXTD_DIR_INFO);
    check!(FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION, F::FILE_ID_EXTD_BOTH_DIR_INFORMATION);
    // The common fields fill_entry writes at fixed offsets.
    type D = F::FILE_DIRECTORY_INFORMATION;
    assert_eq!(offset_of!(D, FileIndex), 4);
    assert_eq!(offset_of!(D, CreationTime), 8);
    assert_eq!(offset_of!(D, ChangeTime), 32);
    assert_eq!(offset_of!(D, EndOfFile), 40);
    assert_eq!(offset_of!(D, AllocationSize), 48);
    assert_eq!(offset_of!(D, FileAttributes), 56);
    assert_eq!(offset_of!(D, FileNameLength), 60);
    assert_eq!(offset_of!(F::FILE_NAMES_INFORMATION, FileNameLength), 8);
    assert_eq!(offset_of!(F::FILE_ID_FULL_DIR_INFORMATION, FileId), 72);
    assert_eq!(offset_of!(F::FILE_ID_BOTH_DIR_INFORMATION, FileId), 96);
    assert_eq!(offset_of!(W::FILE_ID_EXTD_DIR_INFO, FileId), 72);
    assert_eq!(offset_of!(F::FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileId), 72);
}

#[test]
fn file_classes() {
    assert_eq!(info::SIZEOF_FILE_BASIC_INFORMATION, size_of::<F::FILE_BASIC_INFORMATION>());
    assert_eq!(offset_of!(F::FILE_BASIC_INFORMATION, FileAttributes), 32);
    assert_eq!(info::SIZEOF_FILE_STANDARD_INFORMATION, size_of::<F::FILE_STANDARD_INFORMATION>());
    assert_eq!(offset_of!(F::FILE_STANDARD_INFORMATION, NumberOfLinks), 16);
    assert_eq!(offset_of!(F::FILE_STANDARD_INFORMATION, DeletePending), 20);
    assert_eq!(offset_of!(F::FILE_STANDARD_INFORMATION, Directory), 21);
    assert_eq!(info::SIZEOF_FILE_INTERNAL_INFORMATION, size_of::<F::FILE_INTERNAL_INFORMATION>());
    assert_eq!(info::SIZEOF_FILE_POSITION_INFORMATION, size_of::<F::FILE_POSITION_INFORMATION>());
    assert_eq!(info::SIZEOF_FILE_ALL_INFORMATION, size_of::<F::FILE_ALL_INFORMATION>());
    type A = F::FILE_ALL_INFORMATION;
    assert_eq!(offset_of!(A, StandardInformation), 40);
    assert_eq!(offset_of!(A, InternalInformation), 64);
    assert_eq!(offset_of!(A, EaInformation), 72);
    assert_eq!(offset_of!(A, PositionInformation), 80);
    assert_eq!(offset_of!(A, NameInformation) + 4, info::OFFSETOF_FILE_ALL_INFORMATION_NAME);
    assert_eq!(info::SIZEOF_FILE_NAME_INFORMATION, size_of::<F::FILE_NAME_INFORMATION>());
    assert_eq!(info::SIZEOF_FILE_ATTRIBUTE_TAG_INFORMATION, size_of::<S::FILE_ATTRIBUTE_TAG_INFORMATION>());
    assert_eq!(info::SIZEOF_FILE_NETWORK_OPEN_INFORMATION, size_of::<F::FILE_NETWORK_OPEN_INFORMATION>());
    assert_eq!(offset_of!(F::FILE_NETWORK_OPEN_INFORMATION, FileAttributes), 48);
    assert_eq!(info::SIZEOF_FILE_ID_INFORMATION, size_of::<F::FILE_ID_INFORMATION>());
    assert_eq!(offset_of!(F::FILE_ID_INFORMATION, FileId), 8);
    assert_eq!(info::SIZEOF_FILE_STREAM_INFORMATION, size_of::<F::FILE_STREAM_INFORMATION>());
    assert_eq!(offset_of!(F::FILE_STREAM_INFORMATION, StreamName), 24);
}

#[test]
fn volume_classes() {
    assert_eq!(info::SIZEOF_FILE_FS_VOLUME_INFORMATION, size_of::<S::FILE_FS_VOLUME_INFORMATION>());
    assert_eq!(info::OFFSETOF_FILE_FS_VOLUME_INFORMATION_LABEL, offset_of!(S::FILE_FS_VOLUME_INFORMATION, VolumeLabel));
    assert_eq!(offset_of!(S::FILE_FS_VOLUME_INFORMATION, SupportsObjects), 16);
    assert_eq!(info::SIZEOF_FILE_FS_SIZE_INFORMATION, size_of::<S::FILE_FS_SIZE_INFORMATION>());
    assert_eq!(info::SIZEOF_FILE_FS_FULL_SIZE_INFORMATION, size_of::<S::FILE_FS_FULL_SIZE_INFORMATION>());
    assert_eq!(offset_of!(S::FILE_FS_FULL_SIZE_INFORMATION, ActualAvailableAllocationUnits), 16);
    assert_eq!(info::SIZEOF_FILE_FS_ATTRIBUTE_INFORMATION, size_of::<F::FILE_FS_ATTRIBUTE_INFORMATION>());
    assert_eq!(
        info::OFFSETOF_FILE_FS_ATTRIBUTE_INFORMATION_NAME,
        offset_of!(F::FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)
    );
}

#[test]
fn class_numbers() {
    assert_eq!(FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION as i32, F::FileIdExtdBothDirectoryInformation);
    assert_eq!(FILE_ID_EXTD_DIRECTORY_INFORMATION as i32, F::FileIdExtdDirectoryInformation);
    assert_eq!(FILE_ID_INFORMATION as i32, F::FileIdInformation);
    assert_eq!(FILE_NORMALIZED_NAME_INFORMATION as i32, F::FileNormalizedNameInformation);
    assert_eq!(FILE_DISPOSITION_INFORMATION_EX as i32, F::FileDispositionInformationEx);
    assert_eq!(FILE_RENAME_INFORMATION_EX as i32, F::FileRenameInformationEx);
    assert_eq!(FILE_NETWORK_OPEN_INFORMATION as i32, F::FileNetworkOpenInformation);
    assert_eq!(FILE_ATTRIBUTE_TAG_INFORMATION as i32, F::FileAttributeTagInformation);
    assert_eq!(FILE_VALID_DATA_LENGTH_INFORMATION as i32, F::FileValidDataLengthInformation);
    assert_eq!(FILE_STREAM_INFORMATION as i32, F::FileStreamInformation);
    assert_eq!(FILE_FS_FULL_SIZE_INFORMATION as i32, F::FileFsFullSizeInformation);
    assert_eq!(FILE_FS_ATTRIBUTE_INFORMATION as i32, F::FileFsAttributeInformation);
}
