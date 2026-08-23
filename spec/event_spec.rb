# frozen_string_literal: true

RSpec.describe Fanotify::Event do
  def metadata(mask:, fd: -1, pid: 42, infos: "", version: Fanotify::FANOTIFY_METADATA_VERSION,
               event_len: nil, metadata_len: 24)
    event_len ||= metadata_len + infos.bytesize
    [event_len, version, 0, metadata_len, mask, fd, pid].pack("LCCSQll") + infos
  end

  def fid_info(type:, fsid: "12345678", handle_type: 7, handle: "\xaa\xbb".b, name: nil)
    body = fsid + [handle.bytesize, handle_type].pack("Ll") + handle + (name ? "#{name}\0" : "")
    [type, 0, 4 + body.bytesize].pack("CCS") + body
  end

  it "parses concatenated events and converts masks" do
    events = described_class.parse(
      metadata(mask: Fanotify::FAN_OPEN, pid: 1) +
      metadata(mask: Fanotify::FAN_MODIFY | Fanotify::FAN_ONDIR, pid: 2)
    )

    expect(events.map(&:pid)).to eq([1, 2])
    expect(events.last.mask).to contain_exactly(:modify, :ondir)
  end

  it "parses DFID names without treating handles as paths" do
    info = fid_info(type: described_class::INFO_DFID_NAME, name: "file.txt")
    event = described_class.parse(metadata(mask: Fanotify::FAN_CREATE, infos: info)).first

    expect(event.name).to eq("file.txt")
    expect(event.dfid).to have_attributes(fsid: "12345678", type: 7, bytes: "\xaa\xbb".b)
    expect(event.dfid.to_s).to eq("aabb")
  end

  it "parses PIDFD and filesystem error info" do
    pidfd = [described_class::INFO_PIDFD, 0, 8, 9].pack("CCSl")
    error = [described_class::INFO_ERROR, 0, 12, -5, 3].pack("CCSlL")
    event = described_class.parse(metadata(mask: Fanotify::FAN_FS_ERROR, infos: pidfd + error)).first

    expect(event).to have_attributes(pidfd: 9, error: -5, error_count: 3)
  end

  it "keeps PIDFD creation errors separate from owned descriptors" do
    pidfd = [described_class::INFO_PIDFD, 0, 8, -2].pack("CCSl")
    event = described_class.__send__(
      :parse_owned, metadata(mask: Fanotify::FAN_OPEN, infos: pidfd), notifier: nil
    ).first

    expect(event).to have_attributes(pidfd: nil, pidfd_error: -2)
    event.close
  end

  it "parses pre-access byte ranges" do
    range = [described_class::INFO_RANGE, 0, 24, 0, 4096, 8192].pack("CCSLQQ")
    event = described_class.parse(metadata(mask: Fanotify::FAN_PRE_ACCESS, infos: range)).first

    expect(event).to have_attributes(range_offset: 4096, range_count: 8192)
  end

  it "keeps both names from rename records" do
    old_info = fid_info(type: described_class::INFO_OLD_DFID_NAME, name: "old.txt")
    new_info = fid_info(type: described_class::INFO_NEW_DFID_NAME, name: "new.txt")
    event = described_class.parse(metadata(mask: Fanotify::FAN_RENAME, infos: old_info + new_info)).first

    expect(event).to have_attributes(old_name: "old.txt", new_name: "new.txt")
    expect(event.old_dfid).to eq(event.new_dfid)
  end

  it "rejects malformed kernel records" do
    expect { described_class.parse("short") }.to raise_error(ArgumentError, /truncated fanotify metadata/)
    expect { described_class.parse(metadata(mask: 0, version: 99)) }.to raise_error(ArgumentError, /version/)
    expect { described_class.parse(metadata(mask: 0, event_len: 0)) }.to raise_error(ArgumentError, /event length/)
    expect { described_class.parse(metadata(mask: 0, event_len: 48)) }.to raise_error(ArgumentError, /truncated fanotify event/)
    expect { described_class.parse(metadata(mask: 0), own_fds: true) }.to raise_error(ArgumentError, /argument|keyword/)
  end

  it "rejects malformed info records" do
    bad_info = [described_class::INFO_FID, 0, 4].pack("CCS")
    expect { described_class.parse(metadata(mask: 0, infos: bad_info)) }
      .to raise_error(ArgumentError, /truncated FID/)
  end

  it "releases every owned descriptor when any record is invalid" do
    previous_stress = GC.stress
    pipes = 2.times.map { IO.pipe }
    fds = pipes.map do |reader, _writer|
      reader.autoclose = false
      reader.fileno
    end
    buffer = metadata(mask: Fanotify::FAN_OPEN, fd: fds[0], version: 99) +
             metadata(mask: Fanotify::FAN_OPEN, fd: fds[1])
    GC.stress = true

    expect { described_class.__send__(:parse_owned, buffer, notifier: nil) }
      .to raise_error(ArgumentError, /version/)
    fds.each { |fd| expect { IO.for_fd(fd, autoclose: false).stat }.to raise_error(Errno::EBADF) }
  ensure
    GC.stress = previous_stress
    pipes&.each { |_reader, writer| writer.close }
  end

  it "releases transferred descriptors when event construction fails" do
    pipes = 3.times.map { IO.pipe }
    readers = pipes.map(&:first)
    attributes = [
      {raw_mask: Fanotify::FAN_OPEN, fd: readers[0].fileno, pid: 1, infos: [], file_descriptor: readers[0]},
      {
        raw_mask: Fanotify::FAN_OPEN,
        fd: readers[1].fileno,
        pid: 2,
        infos: [{type: described_class::INFO_PIDFD, pidfd: readers[2].fileno,
                 pidfd_descriptor: readers[2]}],
        file_descriptor: readers[1]
      }
    ]
    allow(Fanotify::Native).to receive(:parse).and_return(attributes)
    calls = 0
    allow(described_class).to receive(:new).and_wrap_original do |method, *arguments, **keywords|
      calls += 1
      raise "construction failed" if calls == 2

      method.call(*arguments, **keywords)
    end

    expect { described_class.__send__(:parse_owned, "", notifier: nil) }
      .to raise_error("construction failed")
    expect(readers).to all(be_closed)
  ensure
    pipes&.each { |_reader, writer| writer.close }
  end

  it "keeps parser input stable during compacting GC" do
    previous_stress = GC.stress
    previous_auto_compact = GC.auto_compact
    GC.stress = true
    GC.auto_compact = true

    10.times do
      event = described_class.parse(metadata(mask: Fanotify::FAN_OPEN, pid: 7)).first
      expect(event.pid).to eq(7)
    end
  ensure
    GC.stress = previous_stress
    GC.auto_compact = previous_auto_compact
  end

  it "invalidates the duplicated file IO when the event closes" do
    reader, writer = IO.pipe
    fd = reader.fileno
    reader.autoclose = false
    event = described_class.__send__(
      :parse_owned, metadata(mask: Fanotify::FAN_OPEN, fd:), notifier: nil
    ).first
    file = event.file

    expect(file.fileno).not_to eq(fd)
    event.close
    expect(file).to be_closed
    expect { IO.for_fd(fd, autoclose: false).stat }.to raise_error(Errno::EBADF)
  ensure
    writer&.close
  end
end
