# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

task default: :spec

RSpec::Core::RakeTask.new

begin
  require 'yard'

  YARD::Rake::YardocTask.new do |t|
    t.options = ['--no-private']
    t.files = ['lib/**/*.rb', '-', 'LICENSE']
  end
rescue LoadError
  # no yard, so no yard task
end
