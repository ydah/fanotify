# frozen_string_literal: true

RSpec.describe Fanotify do
  it "loads on unsupported platforms" do
    expect(described_class::VERSION).to eq("0.1.0")
    expect(described_class.supported?).to be(false) unless RUBY_PLATFORM.include?("linux")
  end
end
