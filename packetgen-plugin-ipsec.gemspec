# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'packetgen/plugin/ipsec_version'

Gem::Specification.new do |spec|
  spec.name          = 'packetgen-plugin-ipsec'
  spec.version       = PacketGen::Plugin::IPSEC_VERSION
  spec.authors       = ['Sylvain Daubert']
  spec.email         = ['sylvain.daubert@laposte.net']

  spec.summary       = 'IPsec plugin for packetgen.'
  spec.homepage      = 'https://github.com/sdaubert/packetgen-plugin-ipsec'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.5.0'

  spec.add_dependency 'packetgen', '~>4.0'
end
