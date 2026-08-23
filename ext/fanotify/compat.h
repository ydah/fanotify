#ifndef FANOTIFY_COMPAT_H
#define FANOTIFY_COMPAT_H

#include <fcntl.h>
#include <stdint.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifdef __linux__
#include <linux/fanotify.h>
#include <sys/syscall.h>
#else
struct fanotify_event_metadata {
    uint32_t event_len;
    uint8_t vers;
    uint8_t reserved;
    uint16_t metadata_len;
    uint64_t mask;
    int32_t fd;
    int32_t pid;
};
struct fanotify_response { int32_t fd; uint32_t response; };
#endif

#ifndef FAN_ACCESS
#define FAN_ACCESS 0x00000001
#endif
#ifndef FAN_MODIFY
#define FAN_MODIFY 0x00000002
#endif
#ifndef FAN_ATTRIB
#define FAN_ATTRIB 0x00000004
#endif
#ifndef FAN_CLOSE_WRITE
#define FAN_CLOSE_WRITE 0x00000008
#endif
#ifndef FAN_CLOSE_NOWRITE
#define FAN_CLOSE_NOWRITE 0x00000010
#endif
#ifndef FAN_OPEN
#define FAN_OPEN 0x00000020
#endif
#ifndef FAN_MOVED_FROM
#define FAN_MOVED_FROM 0x00000040
#endif
#ifndef FAN_MOVED_TO
#define FAN_MOVED_TO 0x00000080
#endif
#ifndef FAN_CREATE
#define FAN_CREATE 0x00000100
#endif
#ifndef FAN_DELETE
#define FAN_DELETE 0x00000200
#endif
#ifndef FAN_DELETE_SELF
#define FAN_DELETE_SELF 0x00000400
#endif
#ifndef FAN_MOVE_SELF
#define FAN_MOVE_SELF 0x00000800
#endif
#ifndef FAN_OPEN_EXEC
#define FAN_OPEN_EXEC 0x00001000
#endif
#ifndef FAN_Q_OVERFLOW
#define FAN_Q_OVERFLOW 0x00004000
#endif
#ifndef FAN_FS_ERROR
#define FAN_FS_ERROR 0x00008000
#endif
#ifndef FAN_OPEN_PERM
#define FAN_OPEN_PERM 0x00010000
#endif
#ifndef FAN_ACCESS_PERM
#define FAN_ACCESS_PERM 0x00020000
#endif
#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM 0x00040000
#endif
#ifndef FAN_PRE_ACCESS
#define FAN_PRE_ACCESS 0x00100000
#endif
#ifndef FAN_EVENT_ON_CHILD
#define FAN_EVENT_ON_CHILD 0x08000000
#endif
#ifndef FAN_RENAME
#define FAN_RENAME 0x10000000
#endif
#ifndef FAN_ONDIR
#define FAN_ONDIR 0x40000000
#endif

#ifndef FAN_CLOEXEC
#define FAN_CLOEXEC 0x00000001
#endif
#ifndef FAN_NONBLOCK
#define FAN_NONBLOCK 0x00000002
#endif
#ifndef FAN_CLASS_NOTIF
#define FAN_CLASS_NOTIF 0x00000000
#endif
#ifndef FAN_CLASS_CONTENT
#define FAN_CLASS_CONTENT 0x00000004
#endif
#ifndef FAN_CLASS_PRE_CONTENT
#define FAN_CLASS_PRE_CONTENT 0x00000008
#endif
#ifndef FAN_UNLIMITED_QUEUE
#define FAN_UNLIMITED_QUEUE 0x00000010
#endif
#ifndef FAN_UNLIMITED_MARKS
#define FAN_UNLIMITED_MARKS 0x00000020
#endif
#ifndef FAN_ENABLE_AUDIT
#define FAN_ENABLE_AUDIT 0x00000040
#endif
#ifndef FAN_REPORT_PIDFD
#define FAN_REPORT_PIDFD 0x00000080
#endif
#ifndef FAN_REPORT_TID
#define FAN_REPORT_TID 0x00000100
#endif
#ifndef FAN_REPORT_FID
#define FAN_REPORT_FID 0x00000200
#endif
#ifndef FAN_REPORT_DIR_FID
#define FAN_REPORT_DIR_FID 0x00000400
#endif
#ifndef FAN_REPORT_NAME
#define FAN_REPORT_NAME 0x00000800
#endif
#ifndef FAN_REPORT_DFID_NAME
#define FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
#endif
#ifndef FAN_REPORT_TARGET_FID
#define FAN_REPORT_TARGET_FID 0x00001000
#endif

#ifndef FAN_MARK_ADD
#define FAN_MARK_ADD 0x00000001
#endif
#ifndef FAN_MARK_REMOVE
#define FAN_MARK_REMOVE 0x00000002
#endif
#ifndef FAN_MARK_DONT_FOLLOW
#define FAN_MARK_DONT_FOLLOW 0x00000004
#endif
#ifndef FAN_MARK_ONLYDIR
#define FAN_MARK_ONLYDIR 0x00000008
#endif
#ifndef FAN_MARK_MOUNT
#define FAN_MARK_MOUNT 0x00000010
#endif
#ifndef FAN_MARK_IGNORED_MASK
#define FAN_MARK_IGNORED_MASK 0x00000020
#endif
#ifndef FAN_MARK_IGNORED_SURV_MODIFY
#define FAN_MARK_IGNORED_SURV_MODIFY 0x00000040
#endif
#ifndef FAN_MARK_FLUSH
#define FAN_MARK_FLUSH 0x00000080
#endif
#ifndef FAN_MARK_FILESYSTEM
#define FAN_MARK_FILESYSTEM 0x00000100
#endif
#ifndef FAN_MARK_EVICTABLE
#define FAN_MARK_EVICTABLE 0x00000200
#endif
#ifndef FAN_MARK_IGNORE
#define FAN_MARK_IGNORE 0x00000400
#endif
#ifndef FAN_MARK_INODE
#define FAN_MARK_INODE 0x00000000
#endif

#ifndef FAN_ALLOW
#define FAN_ALLOW 0x01
#endif
#ifndef FAN_DENY
#define FAN_DENY 0x02
#endif
#ifndef FAN_AUDIT
#define FAN_AUDIT 0x10
#endif
#ifndef FANOTIFY_METADATA_VERSION
#define FANOTIFY_METADATA_VERSION 3
#endif
#ifndef FAN_NOFD
#define FAN_NOFD -1
#endif

#ifndef FAN_EVENT_INFO_TYPE_FID
#define FAN_EVENT_INFO_TYPE_FID 1
struct fanotify_event_info_header { uint8_t info_type; uint8_t pad; uint16_t len; };
#endif
#ifndef FAN_EVENT_INFO_TYPE_DFID_NAME
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#endif
#ifndef FAN_EVENT_INFO_TYPE_DFID
#define FAN_EVENT_INFO_TYPE_DFID 3
#endif
#ifndef FAN_EVENT_INFO_TYPE_PIDFD
#define FAN_EVENT_INFO_TYPE_PIDFD 4
#endif
#ifndef FAN_EVENT_INFO_TYPE_ERROR
#define FAN_EVENT_INFO_TYPE_ERROR 5
#endif
#ifndef FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
#define FAN_EVENT_INFO_TYPE_OLD_DFID_NAME 10
#endif
#ifndef FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
#define FAN_EVENT_INFO_TYPE_NEW_DFID_NAME 12
#endif

#endif
