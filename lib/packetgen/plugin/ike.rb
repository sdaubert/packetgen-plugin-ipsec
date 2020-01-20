# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  # This class handles a pseudo-Plugin used to differentiate ESP from IKE Plugins
  # in a UDP datagram with port 4500.
  # @author Sylvain Daubert
  class NonESPMarker < PacketGen::Header::Base
    # @!attribute non_esp_marker
    #  32-bit zero marker to differentiate IKE packet over UDP port 4500 from ESP ones
    #  @return [Integer]
    define_field :non_esp_marker, PacketGen::Types::Int32, default: 0
    # @!attribute body
    #  @return [PacketGen::Types::String,PacketGen::Header::Base]
    define_field :body, PacketGen::Types::String

    # Check non_esp_marker field
    # @see [PacketGen::Header::Base#parse?]
    def parse?
      non_esp_marker.zero?
    end
  end

  # IKE is the Internet Key Exchange protocol (RFC 7296). Ony IKEv2 is supported.
  #
  # A IKE Plugin consists of a Plugin, and a set of payloads. This class
  # handles IKE Plugin. For payloads, see {IKE::Payload}.
  #
  # == IKE Plugin
  # The format of a IKE Plugin is shown below:
  #                       1                   2                   3
  #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |                       IKE SA Initiator's SPI                  |
  #  |                                                               |
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |                       IKE SA Responder's SPI                  |
  #  |                                                               |
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |                          Message ID                           |
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |                            Length                             |
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # A IKE Plugin consists of:
  # * a IKE SA initiator SPI ({#init_spi}, {PacketGen::Types::Int64} type),
  # * a IKE SA responder SPI ({#resp_spi}, {PacketGen::Types::Int64} type),
  # * a Next Payload field ({#next}, {PacketGen::Types::Int8} type),
  # * a Version field ({#version}, {PacketGen::Types::Int8} type, with first 4-bit field
  #   as major number, and last 4-bit field as minor number),
  # * a Exchange type ({#exchange_type}, {PacketGen::Types::Int8} type),
  # * a {#flags} field ({PacketGen::Types::Int8} type),
  # * a Message ID ({#message_id}, {PacketGen::Types::Int32} type),
  # * and a {#length} ({PacketGen::Types::Int32} type).
  #
  # == Create a IKE Plugin
  # === Standalone
  #   ike = PacketGen::Plugin::IKE.new
  # === Classical IKE packet
  #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
  #   # access to IKE Plugin
  #   pkt.ike    # => PacketGen::Plugin::IKE
  # === NAT-T IKE packet
  #   # NonESPMarker is used to insert a 32-bit null field between UDP Plugin
  #   # and IKE one to differentiate it from ESP-in-UDP (see RFC 3948)
  #   pkt = PacketGen.gen('IP').add('UDP').add('NonESPMarker').add('IKE)
  # @author Sylvain Daubert
  class IKE < PacketGen::Header::Base
    # Classical well-known UDP port for IKE
    UDP_PORT1 = 500
    # Well-known UDP port for IKE when NAT is detected
    UDP_PORT2 = 4500

    # Protocols supported by IKE
    PROTOCOLS = {
      'IKE' => 1,
      'AH' => 2,
      'ESP' => 3
    }.freeze

    # Known echange types
    EXCHANGE_TYPES = {
      'IKE_SA_INIT' => 34,
      'IKE_AUTH' => 35,
      'CREATE_CHILD_SA' => 36,
      'INFORMATIONAL' => 37
    }.freeze

    # @!attribute init_spi
    #  64-bit initiator SPI
    #  @return [Integer]
    define_field :init_spi, PacketGen::Types::Int64
    # @!attribute resp_spi
    #  64-bit responder SPI
    #  @return [Integer]
    define_field :resp_spi, PacketGen::Types::Int64
    # @!attribute next
    #  8-bit next payload type
    #  @return [Integer]
    define_field :next, PacketGen::Types::Int8
    # @!attribute version
    #  8-bit IKE version
    #  @return [Integer]
    define_field :version, PacketGen::Types::Int8, default: 0x20
    # @!attribute [r] exchange_type
    #  8-bit exchange type
    #  @return [Integer]
    define_field :exchange_type, PacketGen::Types::Int8Enum, enum: EXCHANGE_TYPES
    # @!attribute flags
    #  8-bit flags
    #  @return [Integer]
    define_field :flags, PacketGen::Types::Int8
    # @!attribute message_id
    #  32-bit message ID
    #  @return [Integer]
    define_field :message_id, PacketGen::Types::Int32
    # @!attribute length
    #  32-bit length of total message (Plugin + payloads)
    #  @return [Integer]
    define_field :length, PacketGen::Types::Int32

    # Defining a body permits using Packet#parse to parse IKE payloads.
    # But this method is hidden as prefered way to access payloads is via #payloads
    define_field :body, PacketGen::Types::String

    # @!attribute mjver
    #  4-bit major version value
    #  @return [Integer]
    # @!attribute mnver
    #  4-bit minor version value
    #  @return [Integer]
    define_bit_fields_on :version, :mjver, 4, :mnver, 4

    # @!attribute rsv1
    #  @return [Integer]
    # @!attribute rsv2
    #  @return [Integer]
    # @!attribute flag_i
    #  bit set in message sent by the original initiator
    #  @return [Boolean]
    # @!attribute flag_r
    #  indicate this message is a response to a message containing the same Message ID
    #  @return [Boolean]
    # @!attribute flag_v
    #  version flag. Ignored by IKEv2 peers, and should be set to 0
    #  @return [Boolean]
    define_bit_fields_on :flags, :rsv1, 2, :flag_r, :flag_v, :flag_i, :rsv2, 3

    # @param [Hash] options
    # @see PacketGen::Header::Base#initialize
    def initialize(options={})
      super
      calc_length unless options[:length]
      self.type = options[:type] if options[:type]
      self.type = options[:exchange_type] if options[:exchange_type]
    end

    alias type exchange_type
    alias type= exchange_type=

    # Get exchange type name
    # @return [String
    def human_exchange_type
      self[:exchange_type].to_human
    end
    alias human_type human_exchange_type

    # Calculate length field
    # @return [Integer]
    def calc_length
      PacketGen::Header::Base.calculate_and_set_length self
    end

    # IKE payloads
    # @return [Array<Payload>]
    def payloads
      payloads = []
      body = self.body
      while body.is_a?(Payload)
        payloads << body
        body = body.body
      end
      payloads
    end

    # @return [String]
    def inspect
      super do |attr|
        case attr
        when :flags
          str_flags = +''
          %w[r v i].each do |flag|
            str_flags << (send("flag_#{flag}?") ? flag.upcase : '.')
          end
          str = PacketGen::Inspect.shift_level
          str << PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''), attr,
                                      str_flags]
        end
      end
    end

    # Toggle +I+ and +R+ flags.
    # @return [self]
    def reply!
      self.flag_r = !self.flag_r?
      self.flag_i = !self.flag_i?
      self
    end

    # @api private
    # @note This method is used internally by PacketGen and should not be
    #       directly called
    # @param [Packet] packet
    # @return [void]
    def added_to_packet(packet)
      return unless packet.is? 'UDP'
      return unless packet.udp.sport.zero?

      packet.udp.sport = if packet.is?('NonESPMarker')
                           UDP_PORT2
                         else
                           UDP_PORT1
                         end
    end
  end

  PacketGen::Header.add_class IKE
  PacketGen::Header.add_class NonESPMarker

  PacketGen::Header::UDP.bind IKE, dport: IKE::UDP_PORT1
  PacketGen::Header::UDP.bind IKE, sport: IKE::UDP_PORT1
  PacketGen::Header::UDP.bind NonESPMarker, dport: IKE::UDP_PORT2
  PacketGen::Header::UDP.bind NonESPMarker, sport: IKE::UDP_PORT2
  NonESPMarker.bind IKE
end

require_relative 'ike/payload'
