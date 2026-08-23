# Fanotify

> [!WARNING]
> Permission events block the process that opened a file until userspace responds.
> A missing response or filesystem access from the handler can deadlock a process or
> the machine. `Fanotify::Notifier#each_event` fails open and closes event descriptors,
> but handlers must still follow the safety rules below.

Ruby 3.2+ C bindings for Linux `fanotify(7)`. The gem supports ordinary
notifications, permission decisions, FID/name records, PIDFD records, rename
records, filesystem errors, and queue-overflow detection.

## Requirements

- Linux 5.1+ and a kernel built with `CONFIG_FANOTIFY`.
- `CAP_SYS_ADMIN` for mount/filesystem marks and all permission events.
- Linux 5.9+ for FID reporting, 5.13+ for unprivileged FID notification groups,
  5.15+ for PIDFD reports, 5.17+ for rename/target FID reports, and 6.14+ for
  experimental pre-access events.
- A C compiler and Linux UAPI headers when installing the gem.

`Fanotify.supported?` checks whether the syscall exists. It does not prove that the
current process has permission for a particular class or mark.

## Installation

```ruby
gem "fanotify"
```

Then run `bundle install`. The native extension is built during installation.

## Notifications

The high-level API uses the unprivileged-compatible FID/name mode:

```ruby
require "fanotify"

Fanotify.watch("/data", events: %i[create delete modify]) do |event|
  puts "#{event.mask.inspect} #{event.name}"
end
```

Use `Notifier` for explicit classes and marks:

```ruby
Fanotify::Notifier.open(class: :notif, report: %i[fid dfid_name]) do |notifier|
  notifier.mark(:add, "/data", events: %i[create delete event_on_child], only_dir: true)
  notifier.each_event { |event| puts event.name }
end
```

`Event#fid`, `#dfid`, `#old_dfid`, and `#new_dfid` are `Fanotify::FileHandle`
values. Handles are comparable and printable as hex, but v1 does not open them with
`open_by_handle_at(2)`.

## Permission decisions

Permission marks require `CAP_SYS_ADMIN`:

```ruby
Fanotify::Notifier.open(class: :content, response_timeout: 5.0) do |notifier|
  notifier.exclude_self!
  notifier.mark(:add, "/data", events: %i[open_perm event_on_child], only_dir: true)

  notifier.each_event do |event|
    event.deny! if event.path&.end_with?(".secret")
    # No explicit decision means allow! when the block exits.
  end
end
```

The default behavior is fail-open:

- A permission event without `allow!` or `deny!` is allowed after the block.
- A handler exception allows the event before the same exception is raised again.
- `defer!` registers an asynchronous decision. The default watchdog allows it after
  five seconds; `response_timeout: nil` disables the watchdog.
- `pending_events` exposes live deferred events.
- `close` allows an unanswered event before closing its descriptors.

`on_error: :deny` changes only the handler-exception decision. It is intentionally
opt-in because application bugs then deny access.

### Handler safety

- Load code, resolve configuration, and open log destinations before adding a
  permission mark. Do not call `require`, open logs, or lazily load files in a handler.
- `exclude_self!` filters self-generated events already read by the notifier. It cannot
  rescue a handler that blocks itself while opening another marked file on the same
  thread.
- Inspect `event.file`, which refers to the kernel-opened descriptor. Do not reopen
  `event.path` for a security decision.
- `event.path` comes from `/proc/self/fd/N` and is informational. Reopening it has a
  TOCTOU race. Deleted paths retain the kernel's `" (deleted)"` suffix.
- Keep handlers bounded. The kernel has no response timeout; the gem watchdog covers
  only events explicitly deferred through this notifier.

## Unsupported and restricted environments

- macOS, BSD, and Windows: `require "fanotify"` succeeds and `supported?` is false;
  constructing a notifier raises `Fanotify::UnsupportedError`.
- Docker/Podman containers: permission events and mount/filesystem marks normally fail
  without `CAP_SYS_ADMIN`; Docker Desktop also runs inside a Linux VM.
- GitHub-hosted runners: unit tests work normally, but system tests need the included
  virtme-ng VM runner.
- WSL2: availability depends on its kernel configuration and the capabilities granted
  to the process.
- Older Linux kernels accept only the flags available in that kernel; unsupported new
  flag combinations fail with the kernel's `Errno::*` exception.

## Development

```sh
bundle install
bundle exec rake test:unit
bundle exec rake rbs
sudo bundle exec rake test:system  # Linux with CAP_SYS_ADMIN
```

The system suite has hard timeouts and covers notification, allow/deny, exception
fail-open, deferred timeout, FID names, unprivileged mode, queue overflow, and 10,000
permission events without fd growth.

Run the same suite in a kernel VM with:

```sh
tools/vm/run.sh              # Linux 6.12
KVER=6.1 tools/vm/run.sh
```

`bundle exec rake gen:constants` regenerates the Ruby constant bindings. Values are
still resolved from the target system's UAPI headers at extension build time.

See `examples/` for audit, permission-scan, and experimental pre-access programs.

## License

[MIT](LICENSE.txt)
