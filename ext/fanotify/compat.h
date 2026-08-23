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

struct fanotify_event_info_header {
    uint8_t info_type;
    uint8_t pad;
    uint16_t len;
};

struct fanotify_response {
    int32_t fd;
    uint32_t response;
};
#endif

#ifndef FAN_ACCESS
#define FAN_ACCESS 0x00000001
#define FAN_MODIFY 0x00000002
#define FAN_ATTRIB 0x00000004
#define FAN_CLOSE_WRITE 0x00000008
#define FAN_CLOSE_NOWRITE 0x00000010
#define FAN_OPEN 0x00000020
#define FAN_MOVED_FROM 0x00000040
#define FAN_MOVED_TO 0x00000080
#define FAN_CREATE 0x00000100
#define FAN_DELETE 0x00000200
#define FAN_DELETE_SELF 0x00000400
#define FAN_MOVE_SELF 0x00000800
#define FAN_OPEN_EXEC 0x00001000
#define FAN_Q_OVERFLOW 0x00004000
#define FAN_FS_ERROR 0x00008000
#define FAN_OPEN_PERM 0x00010000
#define FAN_ACCESS_PERM 0x00020000
#define FAN_OPEN_EXEC_PERM 0x00040000
#define FAN_EVENT_ON_CHILD 0x08000000
#define FAN_RENAME 0x10000000
#define FAN_ONDIR 0x40000000
#endif

#ifndef FAN_PRE_ACCESS
#define FAN_PRE_ACCESS 0x00100000
#endif

#ifndef FAN_CLOEXEC
#define FAN_CLOEXEC 0x00000001
#define FAN_NONBLOCK 0x00000002
#define FAN_CLASS_NOTIF 0x00000000
#define FAN_CLASS_CONTENT 0x00000004
#define FAN_CLASS_PRE_CONTENT 0x00000008
#define FAN_UNLIMITED_QUEUE 0x00000010
#define FAN_UNLIMITED_MARKS 0x00000020
#define FAN_ENABLE_AUDIT 0x00000040
#define FAN_REPORT_PIDFD 0x00000080
#define FAN_REPORT_TID 0x00000100
#define FAN_REPORT_FID 0x00000200
#define FAN_REPORT_DIR_FID 0x00000400
#define FAN_REPORT_NAME 0x00000800
#define FAN_REPORT_TARGET_FID 0x00001000
#endif

#ifndef FAN_REPORT_DFID_NAME
#define FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
#endif

#ifndef FAN_MARK_ADD
#define FAN_MARK_ADD 0x00000001
#define FAN_MARK_REMOVE 0x00000002
#define FAN_MARK_DONT_FOLLOW 0x00000004
#define FAN_MARK_ONLYDIR 0x00000008
#define FAN_MARK_MOUNT 0x00000010
#define FAN_MARK_IGNORED_MASK 0x00000020
#define FAN_MARK_IGNORED_SURV_MODIFY 0x00000040
#define FAN_MARK_FLUSH 0x00000080
#define FAN_MARK_FILESYSTEM 0x00000100
#define FAN_MARK_EVICTABLE 0x00000200
#define FAN_MARK_IGNORE 0x00000400
#define FAN_MARK_INODE 0x00000000
#endif

#ifndef FAN_ALLOW
#define FAN_ALLOW 0x01
#define FAN_DENY 0x02
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
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#define FAN_EVENT_INFO_TYPE_DFID 3
#define FAN_EVENT_INFO_TYPE_PIDFD 4
#define FAN_EVENT_INFO_TYPE_ERROR 5
#define FAN_EVENT_INFO_TYPE_OLD_DFID_NAME 10
#define FAN_EVENT_INFO_TYPE_NEW_DFID_NAME 12
#endif

#endif
