require 'simplecov'
SimpleCov.start do
  add_filter "/spec/"
  add_filter "/vendor/"
end

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'packetgen-plugin-ipsec'

Dir["#{File.dirname(__FILE__)}/support/**/*.rb"].each {|f| require f}

RSpec.configure do |c|
  c.include BindingHelper
  c.include EspHelper
end

def read_packets(filename)
  PacketGen::PcapNG::File.new.read_packets(File.join(__dir__, filename))
end

def read_raw_packets(filename)
  PacketGen::PcapNG::File.new.read_packet_bytes(File.join(__dir__, filename))
end

def force_binary(str)
  PacketGen.force_binary(str)
end
