# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/extensiontask"
require "rbconfig"
require "rspec/core/rake_task"
require "yard"

Rake::ExtensionTask.new("fanotify") do |extension|
  extension.lib_dir = "lib/fanotify"
end

RSpec::Core::RakeTask.new(:spec)
task spec: :compile
YARD::Rake::YardocTask.new

namespace :test do
  RSpec::Core::RakeTask.new(:unit) do |task|
    task.pattern = "spec/**/*_spec.rb"
    task.exclude_pattern = "spec/system/**/*_spec.rb"
  end

  RSpec::Core::RakeTask.new(:system) do |task|
    task.pattern = "spec/system/**/*_spec.rb"
  end

  task unit: :compile
  task system: :compile
end

namespace :gen do
  desc "Regenerate the C constant bindings"
  task :constants do
    sh RbConfig.ruby, "tools/generate_constants.rb"
  end
end

desc "Validate RBS signatures"
task :rbs do
  sh "bundle", "exec", "rbs", "-I", "sig", "validate"
end

task default: "test:unit"
