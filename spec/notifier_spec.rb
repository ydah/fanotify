# frozen_string_literal: true

RSpec.describe Fanotify::Notifier do
  let(:handle) { instance_double(Fanotify::Native::Descriptor, close: nil, closed?: false, read: "buffer") }

  before do
    allow(Fanotify::Native).to receive(:open).and_return(handle)
  end

  it "builds init and event flags from symbols" do
    expected = Fanotify::FAN_CLASS_NOTIF | Fanotify::FAN_REPORT_DFID_NAME | Fanotify::FAN_NONBLOCK
    event_flags = Fanotify::O_RDONLY | Fanotify::O_LARGEFILE | Fanotify::O_CLOEXEC

    described_class.new(class: :notif, report: [:dfid_name], nonblock: true)

    expect(Fanotify::Native).to have_received(:open).with(expected, event_flags)
  end

  it "validates report flag combinations before opening" do
    expect { described_class.new(report: [:name]) }.to raise_error(ArgumentError, /requires :dir_fid/)
    expect { described_class.new(report: [:target_fid]) }.to raise_error(ArgumentError, /requires :dfid_name/)
    expect { described_class.new(class: :content, report: [:fid]) }.to raise_error(ArgumentError, /requires :notif/)
    expect { described_class.new(report: %i[tid pidfd]) }.to raise_error(ArgumentError, /cannot be combined/)
  end

  it "requires one event descriptor access mode" do
    expect { described_class.new(event_flags: [:cloexec]) }.to raise_error(ArgumentError, /one access mode/)
    expect { described_class.new(event_flags: %i[wronly rdwr]) }.to raise_error(ArgumentError, /one access mode/)
  end

  it "rejects ambiguous booleans, callbacks, and durations" do
    expect { described_class.new(nonblock: "yes") }.to raise_error(ArgumentError, /boolean/)
    expect { described_class.new(audit: nil) }.to raise_error(ArgumentError, /boolean/)
    expect { described_class.new(on_overflow: Object.new) }.to raise_error(ArgumentError, /callable/)
    expect { described_class.new(on_overflow: false) }.to raise_error(ArgumentError, /callable/)
    expect { described_class.new(on_error: false) }.to raise_error(ArgumentError, /on_error/)
    expect { described_class.new(response_timeout: false) }.to raise_error(ArgumentError, /positive or nil/)
    expect { described_class.new(response_timeout: Float::INFINITY) }.to raise_error(ArgumentError, /positive or nil/)

    notifier = described_class.new
    expect { notifier.read_events(timeout: "1") }.to raise_error(ArgumentError, /finite number/)
    expect { notifier.read_events(timeout: Float::INFINITY) }.to raise_error(ArgumentError, /finite number/)
    expect { notifier.read_events(timeout: 2_147_484) }.to raise_error(ArgumentError, /finite number/)
    expect { notifier.mark(:add, "/tmp", events: [:open], follow: "false") }
      .to raise_error(ArgumentError, /true or false/)
  end

  it "rejects permission events for notification class" do
    notifier = described_class.new

    expect { notifier.mark(:add, "/tmp", events: [:open_perm]) }
      .to raise_error(ArgumentError, /permission events require/)
  end

  it "restricts pre-access and receive-only masks" do
    notifier = described_class.new(class: :content)

    expect { notifier.mark(:add, "/tmp", events: [:pre_access]) }
      .to raise_error(ArgumentError, /pre_content/)
    expect { notifier.mark(:add, "/tmp", events: [:overflow]) }
      .to raise_error(ArgumentError, /receive-only/)
  end

  it "validates mark-specific event constraints" do
    notifier = described_class.new(report: [:fid])

    expect { notifier.mark(:add, "/tmp", events: [:event_on_child], on: :mount) }
      .to raise_error(ArgumentError, /inode mark/)
    expect { notifier.mark(:add, "/tmp", events: [:fs_error], on: :inode) }
      .to raise_error(ArgumentError, /filesystem mark/)
    expect { notifier.mark(:add, "/tmp", events: [:attrib], on: :mount) }
      .to raise_error(ArgumentError, /mount mark/)
  end

  it "rejects child name events without FID reporting" do
    notifier = described_class.new

    expect { notifier.mark(:add, "/tmp", events: [:create]) }
      .to raise_error(ArgumentError, /require FID reporting/)
    expect { notifier.mark(:add, "/tmp", events: [:delete_self]) }
      .to raise_error(ArgumentError, /require FID reporting/)
  end

  it "invalidates the selectable IO when closed" do
    reader, writer = IO.pipe
    allow(handle).to receive(:to_io).and_return(reader)
    notifier = described_class.new
    io = notifier.to_io

    expect(io.fileno).not_to eq(reader.fileno)
    expect(notifier.close).to be_nil
    expect(io).to be_closed
  ensure
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  it "enables all flags required for target FID reports" do
    expected = Fanotify::FAN_REPORT_DFID_NAME | Fanotify::FAN_REPORT_TARGET_FID | Fanotify::FAN_REPORT_FID

    described_class.new(report: %i[dfid_name target_fid])

    expect(Fanotify::Native).to have_received(:open).with(expected, anything)
  end

  it "closes every parsed event when the overflow callback fails" do
    regular = instance_double(Fanotify::Event, overflow?: false, close: nil, permission?: false)
    overflow = instance_double(Fanotify::Event, overflow?: true, close: nil, permission?: false)
    allow(Fanotify::Event).to receive(:parse_owned).and_return([regular, overflow])
    notifier = described_class.new(on_overflow: ->(_event) { raise "callback failed" })
    allow(notifier).to receive(:warn)

    expect { notifier.read_events }.to raise_error("callback failed")
    expect(regular).to have_received(:close)
    expect(overflow).to have_received(:close)
  end
end
