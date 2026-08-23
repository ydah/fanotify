# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/extensiontask"
require "rspec/core/rake_task"

Rake::ExtensionTask.new("fanotify") do |extension|
  extension.lib_dir = "lib/fanotify"
end

RSpec::Core::RakeTask.new(:spec)
task spec: :compile

task default: :spec
