# frozen_string_literal: true

require "mkmf"

have_header("linux/fanotify.h")
have_const("SYS_fanotify_init", "sys/syscall.h")
have_func("syscall", "unistd.h")
have_func("rb_thread_call_without_gvl", "ruby/thread.h")
create_header
create_makefile("fanotify/fanotify")
