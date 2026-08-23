#include "ruby.h"
#include "ruby/io.h"
#include "ruby/thread.h"
#include "compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <poll.h>
#include <unistd.h>
#endif

#define READ_BUFFER_SIZE (4096 * 16)

typedef struct { int fd; } descriptor_t;
struct owned_fd {
    int fd;
    VALUE descriptor;
    struct owned_fd *next;
};
struct parse_context {
    VALUE buffer;
    VALUE descriptor_roots;
    unsigned char *bytes;
    size_t length;
    int own_fds;
    struct owned_fd *owned_head;
    struct owned_fd *owned_tail;
    struct owned_fd *owned_cursor;
};

static VALUE mFanotify;
static VALUE mNative;
static VALUE cDescriptor;
static VALUE eUnsupported;

void fanotify_define_constants(VALUE module);

static void descriptor_free(void *ptr)
{
    descriptor_t *descriptor = ptr;
    if (descriptor->fd >= 0) close(descriptor->fd);
    xfree(descriptor);
}

static size_t descriptor_size(const void *ptr)
{
    return ptr ? sizeof(descriptor_t) : 0;
}

static const rb_data_type_t descriptor_type = {
    "Fanotify::Native::Descriptor",
    {NULL, descriptor_free, descriptor_size, NULL},
    NULL, NULL, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED
};

static VALUE descriptor_wrap(int fd)
{
    descriptor_t *descriptor;
    VALUE object = TypedData_Make_Struct(cDescriptor, descriptor_t, &descriptor_type, descriptor);
    descriptor->fd = fd;
    return object;
}

static VALUE tracked_descriptor(struct parse_context *context, int fd)
{
    struct owned_fd *owned = malloc(sizeof(*owned));
    if (!owned) {
        close(fd);
        rb_memerror();
    }
    owned->fd = fd;
    owned->descriptor = Qnil;
    owned->next = NULL;
    if (context->owned_tail) context->owned_tail->next = owned;
    else context->owned_head = owned;
    context->owned_tail = owned;
    owned->descriptor = descriptor_wrap(fd);
    rb_ary_push(context->descriptor_roots, owned->descriptor);
    return owned->descriptor;
}

static VALUE prepared_descriptor(struct parse_context *context, int fd)
{
    struct owned_fd *owned = context->owned_cursor;
    if (!owned || owned->fd != fd) rb_raise(rb_eRuntimeError, "fanotify descriptor tracking mismatch");
    context->owned_cursor = owned->next;
    return owned->descriptor;
}

static void release_tracked_descriptors(struct parse_context *context, int close_fds)
{
    struct owned_fd *owned = context->owned_head;
    while (owned) {
        struct owned_fd *next = owned->next;
        if (close_fds) {
            if (!NIL_P(owned->descriptor)) {
                descriptor_t *descriptor;
                TypedData_Get_Struct(owned->descriptor, descriptor_t, &descriptor_type, descriptor);
                descriptor->fd = -1;
            }
            close(owned->fd);
        }
        free(owned);
        owned = next;
    }
    context->owned_head = context->owned_tail = context->owned_cursor = NULL;
}

static descriptor_t *get_descriptor(VALUE self)
{
    descriptor_t *descriptor;
    TypedData_Get_Struct(self, descriptor_t, &descriptor_type, descriptor);
    if (descriptor->fd < 0) rb_raise(rb_eIOError, "closed descriptor");
    return descriptor;
}

static VALUE descriptor_close(VALUE self)
{
    descriptor_t *descriptor;
    TypedData_Get_Struct(self, descriptor_t, &descriptor_type, descriptor);
    if (descriptor->fd >= 0) {
        int fd = descriptor->fd;
        descriptor->fd = -1;
        if (close(fd) < 0) rb_sys_fail("close");
    }
    return Qnil;
}

static VALUE descriptor_closed_p(VALUE self)
{
    descriptor_t *descriptor;
    TypedData_Get_Struct(self, descriptor_t, &descriptor_type, descriptor);
    return descriptor->fd < 0 ? Qtrue : Qfalse;
}

static VALUE descriptor_fileno(VALUE self)
{
    return INT2NUM(get_descriptor(self)->fd);
}

static VALUE descriptor_to_io(VALUE self)
{
    VALUE options = rb_hash_new();
    VALUE args[2];
    rb_hash_aset(options, ID2SYM(rb_intern("autoclose")), Qfalse);
    args[0] = descriptor_fileno(self);
    args[1] = options;
    return rb_funcallv_kw(rb_cIO, rb_intern("for_fd"), 2, args, RB_PASS_KEYWORDS);
}

struct read_args {
    int fd;
    int timeout_ms;
    char *buffer;
    ssize_t result;
    int error;
};

static void *read_without_gvl(void *pointer)
{
    struct read_args *args = pointer;
#ifdef _WIN32
    args->result = -1;
    args->error = ENOSYS;
#else
    struct pollfd pollfd = {args->fd, POLLIN, 0};

    if (args->timeout_ms >= 0) {
        int ready = poll(&pollfd, 1, args->timeout_ms);
        if (ready <= 0) {
            args->result = ready;
            args->error = ready < 0 ? errno : 0;
            return NULL;
        }
    }

    args->result = read(args->fd, args->buffer, READ_BUFFER_SIZE);
    args->error = args->result < 0 ? errno : 0;
#endif
    return NULL;
}

static VALUE perform_read(VALUE pointer)
{
    struct read_args *args = (struct read_args *)pointer;

    rb_thread_call_without_gvl(read_without_gvl, args, RUBY_UBF_IO, NULL);
    if (args->result < 0 && (args->error == EAGAIN || args->error == EWOULDBLOCK)) {
        return Qnil;
    }
    if (args->result < 0) {
        rb_syserr_fail(args->error, "read(fanotify)");
    }
    if (args->result == 0) {
        return Qnil;
    }
    return rb_str_new(args->buffer, args->result);
}

static VALUE free_read_buffer(VALUE pointer)
{
    struct read_args *args = (struct read_args *)pointer;
    xfree(args->buffer);
    return Qnil;
}

static VALUE descriptor_read(VALUE self, VALUE timeout)
{
    descriptor_t *descriptor = get_descriptor(self);
    struct read_args args;

    args.fd = descriptor->fd;
    args.timeout_ms = NIL_P(timeout) ? -1 : NUM2INT(rb_funcall(timeout, rb_intern("*"), 1, INT2NUM(1000)));
    if (args.timeout_ms < -1) rb_raise(rb_eArgError, "timeout must be non-negative");
    args.buffer = ALLOC_N(char, READ_BUFFER_SIZE);
    return rb_ensure(perform_read, (VALUE)&args, free_read_buffer, (VALUE)&args);
}

static VALUE descriptor_mark(VALUE self, VALUE flags, VALUE mask, VALUE dirfd, VALUE path)
{
#ifdef __linux__
    descriptor_t *descriptor = get_descriptor(self);
    const char *pathname = NIL_P(path) ? NULL : StringValueCStr(path);
    long result = syscall(SYS_fanotify_mark, descriptor->fd, NUM2UINT(flags), NUM2ULL(mask), NUM2INT(dirfd), pathname);
    if (result < 0) rb_sys_fail("fanotify_mark");
    return Qnil;
#else
    (void)self; (void)flags; (void)mask; (void)dirfd; (void)path;
    rb_raise(eUnsupported, "fanotify is only available on Linux");
#endif
}

static VALUE descriptor_respond(VALUE self, VALUE event_fd, VALUE response)
{
    descriptor_t *descriptor = get_descriptor(self);
    struct fanotify_response value = {NUM2INT(event_fd), NUM2UINT(response)};
    ssize_t written;
    do {
        written = write(descriptor->fd, &value, sizeof(value));
    } while (written < 0 && errno == EINTR);
    if (written < 0) rb_sys_fail("write(fanotify response)");
    if ((size_t)written != sizeof(value)) rb_raise(rb_eIOError, "short fanotify response write");
    return Qnil;
}

static VALUE native_supported_p(VALUE self)
{
    (void)self;
#ifdef __linux__
    int fd = (int)syscall(SYS_fanotify_init, FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                          O_RDONLY | O_CLOEXEC | O_LARGEFILE);
    if (fd >= 0) {
        close(fd);
        return Qtrue;
    }
    return (errno == ENOSYS || errno == EOPNOTSUPP) ? Qfalse : Qtrue;
#else
    return Qfalse;
#endif
}

static VALUE native_open(VALUE self, VALUE flags, VALUE event_flags)
{
    (void)self;
#ifdef __linux__
    int fd = (int)syscall(SYS_fanotify_init, NUM2UINT(flags), NUM2UINT(event_flags));
    if (fd < 0) {
        if (errno == ENOSYS || errno == EOPNOTSUPP) rb_raise(eUnsupported, "fanotify is not supported by this kernel");
        rb_sys_fail("fanotify_init");
    }
    return descriptor_wrap(fd);
#else
    (void)flags; (void)event_flags;
    rb_raise(eUnsupported, "fanotify is only available on Linux");
#endif
}

static VALUE hash(void)
{
    return rb_hash_new();
}

static void set(VALUE target, const char *key, VALUE value)
{
    rb_hash_aset(target, ID2SYM(rb_intern(key)), value);
}

static VALUE parse_info(const unsigned char *bytes, size_t length, struct parse_context *context)
{
    struct fanotify_event_info_header header;
    VALUE info = hash();
    memcpy(&header, bytes, sizeof(header));
    set(info, "type", UINT2NUM(header.info_type));

    if (header.info_type == FAN_EVENT_INFO_TYPE_PIDFD) {
        int32_t pidfd;
        if (length < sizeof(header) + sizeof(pidfd)) rb_raise(rb_eArgError, "truncated PIDFD info record");
        memcpy(&pidfd, bytes + sizeof(header), sizeof(pidfd));
        set(info, "pidfd", INT2NUM(pidfd));
        if (context->own_fds && pidfd >= 0)
            set(info, "pidfd_descriptor", prepared_descriptor(context, pidfd));
    } else if (header.info_type == FAN_EVENT_INFO_TYPE_ERROR) {
        int32_t error;
        uint32_t count;
        if (length < sizeof(header) + sizeof(error) + sizeof(count)) rb_raise(rb_eArgError, "truncated ERROR info record");
        memcpy(&error, bytes + sizeof(header), sizeof(error));
        memcpy(&count, bytes + sizeof(header) + sizeof(error), sizeof(count));
        set(info, "error", INT2NUM(error));
        set(info, "error_count", UINT2NUM(count));
    } else if (header.info_type == FAN_EVENT_INFO_TYPE_FID ||
               header.info_type == FAN_EVENT_INFO_TYPE_DFID ||
               header.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
               header.info_type == FAN_EVENT_INFO_TYPE_OLD_DFID_NAME ||
               header.info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME) {
        uint32_t handle_bytes;
        int32_t handle_type;
        size_t fixed = sizeof(header) + 8 + sizeof(handle_bytes) + sizeof(handle_type);
        size_t name_offset;
        const unsigned char *nul;
        if (length < fixed) rb_raise(rb_eArgError, "truncated FID info record");
        memcpy(&handle_bytes, bytes + sizeof(header) + 8, sizeof(handle_bytes));
        memcpy(&handle_type, bytes + sizeof(header) + 8 + sizeof(handle_bytes), sizeof(handle_type));
        if (handle_bytes > length - fixed) rb_raise(rb_eArgError, "invalid file handle length");
        set(info, "fsid", rb_str_new((const char *)bytes + sizeof(header), 8));
        set(info, "handle_type", INT2NUM(handle_type));
        set(info, "handle", rb_str_new((const char *)bytes + fixed, handle_bytes));
        name_offset = fixed + handle_bytes;
        if (header.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
            header.info_type == FAN_EVENT_INFO_TYPE_OLD_DFID_NAME ||
            header.info_type == FAN_EVENT_INFO_TYPE_NEW_DFID_NAME) {
            nul = memchr(bytes + name_offset, '\0', length - name_offset);
            if (!nul) rb_raise(rb_eArgError, "unterminated DFID name");
            set(info, "name", rb_str_new((const char *)bytes + name_offset, nul - (bytes + name_offset)));
        }
    } else if (header.info_type == FAN_EVENT_INFO_TYPE_RANGE) {
        uint64_t offset;
        uint64_t count;
        if (length < sizeof(header) + 4 + sizeof(offset) + sizeof(count))
            rb_raise(rb_eArgError, "truncated RANGE info record");
        memcpy(&offset, bytes + sizeof(header) + 4, sizeof(offset));
        memcpy(&count, bytes + sizeof(header) + 4 + sizeof(offset), sizeof(count));
        set(info, "range_offset", ULL2NUM(offset));
        set(info, "range_count", ULL2NUM(count));
    } else {
        set(info, "raw", rb_str_new((const char *)bytes + sizeof(header), length - sizeof(header)));
    }
    return info;
}

static void prepare_descriptors(struct parse_context *context, const unsigned char *bytes, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        struct fanotify_event_metadata metadata;
        size_t info_offset;
        if (length - offset < sizeof(metadata)) break;
        memcpy(&metadata, bytes + offset, sizeof(metadata));
        if (metadata.fd >= 0) tracked_descriptor(context, metadata.fd);
        if (metadata.metadata_len < sizeof(metadata) || metadata.event_len < metadata.metadata_len ||
            metadata.event_len > length - offset) break;

        info_offset = offset + metadata.metadata_len;
        while (info_offset < offset + metadata.event_len) {
            struct fanotify_event_info_header header;
            int32_t pidfd;
            if (offset + metadata.event_len - info_offset < sizeof(header)) break;
            memcpy(&header, bytes + info_offset, sizeof(header));
            if (header.len < sizeof(header) || header.len > offset + metadata.event_len - info_offset) break;
            if (header.info_type == FAN_EVENT_INFO_TYPE_PIDFD && header.len >= sizeof(header) + sizeof(pidfd)) {
                memcpy(&pidfd, bytes + info_offset + sizeof(header), sizeof(pidfd));
                if (pidfd >= 0) tracked_descriptor(context, pidfd);
            }
            info_offset += header.len;
        }
        offset += metadata.event_len;
    }
    context->owned_cursor = context->owned_head;
}

static VALUE parse_buffer(VALUE context_value)
{
    struct parse_context *context = (struct parse_context *)context_value;
    const unsigned char *bytes = context->bytes;
    size_t length = context->length;
    size_t offset = 0;
    VALUE events = rb_ary_new();

    if (context->own_fds) prepare_descriptors(context, bytes, length);

    while (offset < length) {
        struct fanotify_event_metadata metadata;
        size_t info_offset;
        VALUE event;
        VALUE infos;

        if (length - offset < sizeof(metadata)) rb_raise(rb_eArgError, "truncated fanotify metadata");
        memcpy(&metadata, bytes + offset, sizeof(metadata));
        if (metadata.vers != FANOTIFY_METADATA_VERSION) rb_raise(rb_eArgError, "unsupported fanotify metadata version");
        if (metadata.metadata_len < sizeof(metadata) || metadata.event_len < metadata.metadata_len)
            rb_raise(rb_eArgError, "invalid fanotify event length");
        if (metadata.event_len > length - offset) rb_raise(rb_eArgError, "truncated fanotify event");

        event = hash();
        infos = rb_ary_new();
        set(event, "raw_mask", ULL2NUM(metadata.mask));
        set(event, "fd", INT2NUM(metadata.fd));
        set(event, "pid", INT2NUM(metadata.pid));
        set(event, "infos", infos);
        if (context->own_fds && metadata.fd >= 0)
            set(event, "file_descriptor", prepared_descriptor(context, metadata.fd));

        info_offset = offset + metadata.metadata_len;
        while (info_offset < offset + metadata.event_len) {
            struct fanotify_event_info_header header;
            if (offset + metadata.event_len - info_offset < sizeof(header))
                rb_raise(rb_eArgError, "truncated fanotify info header");
            memcpy(&header, bytes + info_offset, sizeof(header));
            if (header.len < sizeof(header) || header.len > offset + metadata.event_len - info_offset)
                rb_raise(rb_eArgError, "invalid fanotify info length");
            rb_ary_push(infos, parse_info(bytes + info_offset, header.len, context));
            info_offset += header.len;
        }

        rb_ary_push(events, event);
        offset += metadata.event_len;
    }
    return events;
}

static VALUE native_parse(int argc, VALUE *argv, VALUE self)
{
    VALUE own_fds_value;
    VALUE events;
    int exception;
    struct parse_context context = {Qnil, Qnil, NULL, 0, 0, NULL, NULL, NULL};
    (void)self;

    rb_scan_args(argc, argv, "11", &context.buffer, &own_fds_value);
    StringValue(context.buffer);
    context.length = (size_t)RSTRING_LEN(context.buffer);
    context.descriptor_roots = rb_ary_new();
    context.bytes = ALLOC_N(unsigned char, context.length ? context.length : 1);
    memcpy(context.bytes, RSTRING_PTR(context.buffer), context.length);
    context.own_fds = RTEST(own_fds_value);
    rb_gc_register_address(&context.descriptor_roots);
    events = rb_protect(parse_buffer, (VALUE)&context, &exception);
    release_tracked_descriptors(&context, exception);
    rb_gc_unregister_address(&context.descriptor_roots);
    xfree(context.bytes);
    if (exception) rb_jump_tag(exception);
    RB_GC_GUARD(context.buffer);
    RB_GC_GUARD(context.descriptor_roots);
    return events;
}

void Init_fanotify(void)
{
    mFanotify = rb_define_module("Fanotify");
    eUnsupported = rb_const_get(mFanotify, rb_intern("UnsupportedError"));
    mNative = rb_define_module_under(mFanotify, "Native");
    cDescriptor = rb_define_class_under(mNative, "Descriptor", rb_cObject);
    rb_undef_alloc_func(cDescriptor);
    rb_define_method(cDescriptor, "close", descriptor_close, 0);
    rb_define_method(cDescriptor, "closed?", descriptor_closed_p, 0);
    rb_define_method(cDescriptor, "fileno", descriptor_fileno, 0);
    rb_define_method(cDescriptor, "to_io", descriptor_to_io, 0);
    rb_define_method(cDescriptor, "read", descriptor_read, 1);
    rb_define_method(cDescriptor, "mark", descriptor_mark, 4);
    rb_define_method(cDescriptor, "respond", descriptor_respond, 2);
    rb_define_singleton_method(mNative, "supported?", native_supported_p, 0);
    rb_define_singleton_method(mNative, "open", native_open, 2);
    rb_define_singleton_method(mNative, "parse", native_parse, -1);
    fanotify_define_constants(mNative);
}
