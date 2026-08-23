<h1 align="center">Fanotify</h1>

<p align="center">
  <strong>Safe Ruby bindings for Linux fanotify</strong>
</p>

<p align="center">
  <a href="https://rubygems.org/gems/fanotify"><img src="https://img.shields.io/gem/v/fanotify.svg?colorB=319e8c" alt="Gem Version"></a>
  <a href="https://rubygems.org/gems/fanotify"><img src="https://img.shields.io/gem/dt/fanotify.svg" alt="Downloads"></a>
  <a href="https://github.com/ydah/fanotify/actions/workflows/main.yml"><img src="https://github.com/ydah/fanotify/actions/workflows/main.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/ruby-%3E%3D%203.2-ruby.svg" alt="Ruby Version">
  <img src="https://img.shields.io/badge/platform-Linux-yellow.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#permission-events">Permission Events</a> ·
  <a href="#development">Development</a>
</p>

---

Fanotify provides Ruby 3.2+ C bindings for Linux `fanotify(7)`. It monitors
filesystem activity, reports file identity and name records, and safely handles
permission decisions that can block other processes.

> [!WARNING]
> Permission events block the process accessing a file until userspace responds.
> A missing response or filesystem access from the handler can deadlock a process
> or the machine. `Fanotify::Notifier#each_event` fails open and closes event
> descriptors, but handlers must still follow the safety rules below.

## Features

- High-level file watching with `Fanotify.watch`
- Notification and permission event groups
- Safe allow, deny, deferred, timeout, and fail-open decisions
- FID, filename, rename, target FID, and PIDFD records
- Filesystem error and queue-overflow reporting
- Linux 6.14 pre-access range events for hierarchical storage managers
- Native extension with no runtime gem dependencies

## Installation

Add the gem to your Gemfile:

```ruby
gem "fanotify"
```

Then install it:

```sh
bundle install
```

The native extension is built during installation.

### Requirements

- Linux 5.1+ with `CONFIG_FANOTIFY`
- Ruby 3.2+
- A C compiler and Linux UAPI headers
- `CAP_SYS_ADMIN` for mount/filesystem marks and all permission events

| Feature | Minimum Linux version |
|---------|-----------------------|
| FID reporting | 5.9 |
| Unprivileged FID notification groups | 5.13 |
| PIDFD reports | 5.15 |
| Rename and target FID reports | 5.17 |
| Experimental pre-access events | 6.14 |

`Fanotify.supported?` checks whether the syscall exists. It does not prove that
the current process can create a particular group or mark.

## Quick Start

Watch a directory for ordinary notifications:

```ruby
require "fanotify"

Fanotify.watch("/data", events: %i[create delete modify]) do |event|
  puts "#{event.mask.inspect} #{event.name}"
end
```

Use `Notifier` when you need explicit classes, reports, or mark flags:

```ruby
Fanotify::Notifier.open(class: :notif, report: %i[fid dfid_name]) do |notifier|
  notifier.mark(:add, "/data", events: %i[create delete event_on_child], only_dir: true)
  notifier.each_event { |event| puts event.name }
end
```

`Event#fid`, `#dfid`, `#old_dfid`, and `#new_dfid` are comparable
`Fanotify::FileHandle` values printable as hex. Version 1 does not open them with
`open_by_handle_at(2)`.

## Permission Events

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

### Failure Behavior

The default behavior is fail-open:

- An unanswered permission event is allowed after the handler block returns.
- A handler exception allows the event before re-raising the same exception.
- `defer!` registers an asynchronous decision. The watchdog allows it after five
  seconds by default. `response_timeout: nil` disables the deadline, while GC
  fail-open cleanup remains active.
- `pending_events` exposes live deferred events.
- `close` allows unanswered events and interrupts threads blocked in `read_events`
  with `Fanotify::Error`.
- A failed response write closes the entire notification group, releasing every
  process waiting on it.

`on_error: :deny` changes only the handler-exception decision. It is opt-in
because application errors then deny filesystem access.

### Handler Safety

- Load code, resolve configuration, and open log destinations before adding a
  permission mark. Do not call `require`, open logs, or lazily load files inside
  the handler.
- Call `exclude_self!` to filter self-generated events already read by the
  notifier. It cannot rescue a handler that blocks itself while opening another
  marked file on the same thread.
- Inspect `event.file`, which duplicates the kernel-opened descriptor and closes
  with the event. Do not reopen `event.path` for a security decision.
- Treat `event.path` as informational. It comes from `/proc/self/fd/N`, reopening
  it has a TOCTOU race, and deleted paths keep the kernel's `" (deleted)"` suffix.
- Keep handlers bounded. The kernel has no response timeout; the gem watchdog
  covers only events deferred through this notifier.

### Pre-access Events

Linux 6.14 pre-access events expose the kernel-reported access range through
`Event#range_offset` and `Event#range_count`. The range can be larger than the
application-level read request. These events also require an HSM-capable
filesystem such as ext4, XFS, or Btrfs. See [`examples/lazy_fetch.rb`](examples/lazy_fetch.rb).

## Platform Notes

| Environment | Behavior |
|-------------|----------|
| macOS, BSD, Windows | `require "fanotify"` succeeds and `supported?` is false; constructing a notifier raises `Fanotify::UnsupportedError`. |
| Docker or Podman | Permission events and mount/filesystem marks normally require `CAP_SYS_ADMIN`; Docker Desktop runs inside a Linux VM. |
| GitHub-hosted runners | Unit tests run normally; system tests use the included virtme-ng kernel VM. |
| WSL2 | Availability depends on the kernel configuration and process capabilities. |
| Older Linux kernels | Unsupported flags and combinations raise the kernel's `Errno::*` exception. |

## Examples

- [`examples/audit_logger.rb`](examples/audit_logger.rb) — log filesystem activity
- [`examples/malware_scan.rb`](examples/malware_scan.rb) — inspect and decide permission events
- [`examples/lazy_fetch.rb`](examples/lazy_fetch.rb) — materialize Linux 6.14 pre-access ranges

## Development

```sh
bundle install
bundle exec rake test:unit
bundle exec rake rbs
sudo bundle exec rake test:system  # Linux with CAP_SYS_ADMIN
```

The system suite has hard timeouts and covers notifications, permission
decisions, exception fail-open, deferred cleanup, FID names, unprivileged mode,
queue overflow, and descriptor leak detection.

Run it in a kernel VM with:

```sh
tools/vm/run.sh              # Linux 6.12
KVER=6.1 tools/vm/run.sh
```

Regenerate Ruby constant bindings with `bundle exec rake gen:constants`. Values
are resolved from the target system's UAPI headers when the extension is built.

Reference throughput for 10,000 distinct `FAN_OPEN` FID events was 266,374
events/s on Ruby 3.4.10 and Linux 6.8 arm64 in a Docker Desktop VM. Benchmark the
deployment host with `bundle exec ruby benchmark/events.rb`; handler work and
event shape dominate real throughput.

## Contributing

Bug reports and pull requests are welcome at https://github.com/ydah/fanotify.

## License

Released under the [MIT License](LICENSE.txt).
