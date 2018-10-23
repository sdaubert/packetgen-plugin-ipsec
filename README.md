[![Build Status](https://travis-ci.com/sdaubert/packetgen-plugin-ipsec.svg?branch=master)](https://travis-ci.com/sdaubert/packetgen-plugin-ipsec)

# packetgen-plugin-ipsec

**Warning:** this repository is a work-in-progress. It will be available with packetgen3.

This is a plugin for [PacketGen gem](https://github.com/sdaubert/packetgen). It adds two protocols:

* `PacketGen::Plugin::ESP`: IP Encapsulating Security Payload ([RFC 4303](https://tools.ietf.org/html/rfc4303)),
* `PacketGen::Plugin::IKE`: Internet Key Exchange v2 ([RFC 7296](https://tools.ietf.org/html/rfc7296)).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'packetgen-plugin-ipsec'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install packetgen-plugin-ipsec

## Usage

First, you have to require packetgen-plugin-ipsec:

```ruby
require 'packetgen-plugin-ipsec'
```

### Parse an ESP or IKE packet

```ruby
pkt = PacketGen.parse(str)
```

### Read a PcapNG file containing ESP and/or IKE packets

```ruby
pkts = PacketGen.read('ipsec.pcapng')
```

### Access to ESP and IKE headers

```ruby
pkt.esp   #=> PacketGen::Plugin::ESP
pkt.ike   #=> PacketGen::Plugin::IKE
```

### Forge packets

#### ESP (transport mode)

```ruby
pkt = PacketGen.gen('IP', src: '1.1.1.1', dst: '2.2.2.2').
                add('ESP', spi: 0xff456e01, sn: 12345678).
                add('UDP', dport: 4567, sport: 45362, body 'abcdef')
cipher = OpenSSL::Cipher.new('aes-128-cbc')
cipher.encrypt
cipher.key = 16bytes_key
iv = 16bytes_iv
pkt.esp.esp.encrypt! cipher, iv
pkt.to_w
```

#### IKE (IKE_SA_INIT)

```ruby
pkt = PacketGen.gen('IP', src: '1.1.1.1', dst: '2.2.2.2').
                add('UDP').
                add('IKE', init_spi: spi, flags: 8).
                add('IKE::SA').
                add('IKE::KE', group: 'ECP256', content: key_ex_data).
                add('IKE::Nonce', content: nonce_data)
pkt.ike_sa.proposals << { num: 1, protocol: 'IKE' }
pkt.ike_sa.proposals.first.transforms << { type: 'ENCR', id: 'AES_CTR' }
pkt.ike_sa.proposals[0].transforms[0].attributes << { type: 0x800e, value: 128 }
pkt.to_w
```

## See also

API documentation: http://www.rubydoc.info/gems/packetgen-plugin-ipsec

## License

MIT License (see [LICENSE](https://github.com/sdaubert/packetgen-plugin-ipsec/blob/master/LICENSE))

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sdaubert/packetgen-plugin-ipsec.
