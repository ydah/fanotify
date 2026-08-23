# frozen_string_literal: true

RSpec.describe Fanotify do
  it "loads on unsupported platforms" do
    expect(described_class::VERSION).to eq("0.1.0")
    expect(described_class.supported?).to be(false) unless RUBY_PLATFORM.include?("linux")
  end

  it "configures the high-level watcher for named FID events" do
    notifier = instance_double(Fanotify::Notifier, mark: nil, each_event: nil)
    allow(Fanotify::Notifier).to receive(:open).and_yield(notifier)
    handler = proc { |_event| }

    described_class.watch("/tmp", events: [:create], &handler)

    expect(Fanotify::Notifier).to have_received(:open).with(class: :notif, report: %i[fid dfid_name])
    expect(notifier).to have_received(:mark)
      .with(:add, "/tmp", events: %i[create event_on_child], only_dir: true)
    expect(notifier).to have_received(:each_event)
  end
end
