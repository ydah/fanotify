# frozen_string_literal: true

require "timeout"

RSpec.describe "permission event safety" do
  let(:handle) do
    instance_double(Fanotify::Native::Descriptor, close: nil, closed?: false, respond: nil)
  end
  let(:notifier) { Fanotify::Notifier.new(class: :content, response_timeout: nil) }

  before do
    allow(Fanotify::Native).to receive(:open).and_return(handle)
  end

  def event(notifier:, pid: 123, mask: Fanotify::FAN_OPEN_PERM, fd: 37)
    Fanotify::Event.new({raw_mask: mask, fd:, pid:, infos: []}, notifier:)
  end

  def one_event_then_stop(notifier, value)
    calls = 0
    allow(notifier).to receive(:read_events) do
      calls += 1
      calls == 1 ? [value] : raise(StopIteration)
    end
  end

  it "allows an unanswered event when the block ends" do
    value = event(notifier:)
    one_event_then_stop(notifier, value)

    notifier.each_event { |_event| }
    expect(handle).to have_received(:respond).with(37, Fanotify::FAN_ALLOW)
    expect(value).to be_responded
  end

  it "uses the configured fail-open or fail-closed response on handler errors" do
    deny_notifier = Fanotify::Notifier.new(class: :content, on_error: :deny, response_timeout: nil)
    value = event(notifier: deny_notifier)
    one_event_then_stop(deny_notifier, value)

    expect { deny_notifier.each_event { raise "handler failed" } }.to raise_error("handler failed")
    expect(handle).to have_received(:respond).with(37, Fanotify::FAN_DENY)
  end

  it "supports explicit audited responses" do
    value = event(notifier:)

    value.deny!(audit: true)

    expect(handle).to have_received(:respond).with(37, Fanotify::FAN_DENY | Fanotify::FAN_AUDIT)
    expect { value.allow! }.to raise_error(Fanotify::Error, /already been responded/)
  end

  it "tracks deferred events until they are answered" do
    value = event(notifier:)

    expect(value.defer!).to equal(value)
    expect(notifier.pending_events).to eq([value])
    value.allow!
    expect(notifier.pending_events).to be_empty
  end

  it "answers a deferred event before propagating a handler error" do
    value = event(notifier:)
    one_event_then_stop(notifier, value)

    expect { notifier.each_event { |received| received.defer! && raise("handler failed") } }
      .to raise_error("handler failed")
    expect(value).to be_responded
    expect(notifier.pending_events).to be_empty
  end

  it "allows deferred events after the response timeout" do
    timed_notifier = Fanotify::Notifier.new(class: :content, response_timeout: 0.01)
    value = event(notifier: timed_notifier)

    value.defer!
    expect do
      Timeout.timeout(1) { sleep 0.01 until value.responded? }
    end.to output(/response timeout expired/).to_stderr_from_any_process
    expect(value).to be_responded
  ensure
    timed_notifier&.close
  end

  it "never yields self-generated events after exclusion" do
    value = event(notifier:, pid: Process.pid)
    yielded = false
    notifier.exclude_self!
    one_event_then_stop(notifier, value)

    notifier.each_event { yielded = true }
    expect(yielded).to be(false)
    expect(handle).to have_received(:respond).with(37, Fanotify::FAN_ALLOW)
  end

  it "fails open when a permission event is closed directly" do
    value = event(notifier:)

    value.close

    expect(handle).to have_received(:respond).with(37, Fanotify::FAN_ALLOW)
  end
end
