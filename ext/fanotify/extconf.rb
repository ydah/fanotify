# frozen_string_literal: true

require "mkmf"

have_func("rb_thread_call_without_gvl", "ruby/thread.h")
create_header
create_makefile("fanotify/fanotify")
