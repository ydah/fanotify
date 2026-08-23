# frozen_string_literal: true

RSpec.describe Fanotify::Notifier do
  let(:handle) { instance_double(Fanotify::Native::Descriptor, close: nil, closed?: false) }

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
  end

  it "rejects permission events for notification class" do
    notifier = described_class.new

    expect { notifier.mark(:add, "/tmp", events: [:open_perm]) }
      .to raise_error(ArgumentError, /permission events require/)
  end

  it "rejects child name events without FID reporting" do
    notifier = described_class.new

    expect { notifier.mark(:add, "/tmp", events: [:create]) }
      .to raise_error(ArgumentError, /require FID reporting/)
  end

  it "enables all flags required for target FID reports" do
    expected = Fanotify::FAN_REPORT_DFID_NAME | Fanotify::FAN_REPORT_TARGET_FID | Fanotify::FAN_REPORT_FID

    described_class.new(report: %i[dfid_name target_fid])

    expect(Fanotify::Native).to have_received(:open).with(expected, anything)
  end
end
