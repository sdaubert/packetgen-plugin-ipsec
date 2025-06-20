# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # TrafficSelector substructure, as defined in RFC 7296, §3.13.1:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |   TS Type     |IP Protocol ID*|       Selector Length         |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |           Start Port*         |           End Port*           |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                         Starting Address*                     ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                         Ending Address*                       ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # @author Sylvain Daubert
    class TrafficSelector < BinStruct::Struct
      # IPv4 traffic selector type
      TS_IPV4_ADDR_RANGE = 7
      # IPv6 traffic selector type
      TS_IPV6_ADDR_RANGE = 8

      # @!attribute [r] type
      #  8-bit TS type
      #  @return [Integer]
      define_attr :type, BinStruct::Int8, default: 7
      # @!attribute [r] protocol
      #  8-bit protocol ID
      #  @return [Integer]
      define_attr :protocol, BinStruct::Int8, default: 0
      # @!attribute length
      #  16-bit Selector Length
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute start_port
      #  16-bit Start port
      #  @return [Integer]
      define_attr :start_port, BinStruct::Int16, default: 0
      # @!attribute end_port
      #  16-bit End port
      #  @return [Integer]
      define_attr :end_port, BinStruct::Int16, default: 65_535
      # @!attribute start_addr
      #  starting address
      #  @return [IP::Addr, IPv6::Addr]
      define_attr :start_addr, PacketGen::Header::IP::Addr
      # @!attribute end_addr
      #  starting address
      #  @return [IP::Addr, IPv6::Addr]
      define_attr :end_addr, PacketGen::Header::IP::Addr

      # @param [Hash] options
      # @options[Integer] :type
      # @options[Integer] :protocol
      # @options[Integer] :length
      # @option [String] :start_addr
      # @option [String] :end_addr
      # @option [Range] :ports port range
      def initialize(options={}) # rubocop:disable Metrics/AbcSize
        super
        select_addr options
        self[:start_addr].from_human(options[:start_addr]) if options[:start_addr]
        self[:end_addr].from_human(options[:end_addr]) if options[:end_addr]
        self.type = options[:type] if options[:type]
        self.protocol = options[:protocol] if options[:protocol]
        self[:length].value = sz unless options[:length]
        return unless options[:ports]

        self.start_port = options[:ports].begin
        self.end_port = options[:ports].end
      end

      # Populate object from a string
      # @param [String] str
      # @return [self]
      def read(str)
        super
        select_addr_from_type type
        super
      end

      undef type=, protocol=

      # Set type
      # @param [Integer,String] value
      # @return [Integer]
      def type=(value)
        type = case value
               when Integer
                 value
               else
                 c = self.class.constants.grep(/TS_#{value.upcase}/).first
                 c ? self.class.const_get(c) : nil
               end
        raise ArgumentError, "unknown type #{value.inspect}" unless type

        select_addr_from_type type
        self[:type].value = type
      end

      # Set protocol
      # @param [Integer,String] value
      # @return [Integer]
      def protocol=(value)
        protocol = case value
                   when Integer
                     value
                   else
                     PacketGen::Proto.getprotobyname(value)
                   end
        raise ArgumentError, "unknown protocol #{value.inspect}" unless protocol

        self[:protocol].value = protocol
      end

      # Get a human readable string
      # @return [String]
      def to_human
        h = start_addr << '-' << end_addr
        unless human_protocol.empty?
          h << "/#{human_protocol}"
          h << "[#{start_port}-#{end_port}]" if (start_port..end_port) != (0..65_535)
        end
        h
      end

      # Get human readable protocol name. If protocol ID is 0, an empty string
      # is returned.
      # @return [String]
      def human_protocol
        if protocol.zero?
          ''
        else
          PacketGen::Proto.getprotobynumber(protocol) || protocol.to_s
        end
      end

      # Get human readable TS type
      # @return [String]
      def human_type
        case type
        when TS_IPV4_ADDR_RANGE
          'IPv4'
        when TS_IPV6_ADDR_RANGE
          'IPv6'
        else
          "type #{type}"
        end
      end

      private

      def select_addr_from_type(type)
        case type
        when TS_IPV4_ADDR_RANGE, 'IPV4', 'IPv4', 'ipv4', nil
          self[:start_addr] = PacketGen::Header::IP::Addr.new unless self[:start_addr].is_a?(PacketGen::Header::IP::Addr)
          self[:end_addr] = PacketGen::Header::IP::Addr.new unless self[:end_addr].is_a?(PacketGen::Header::IP::Addr)
        when TS_IPV6_ADDR_RANGE, 'IPV6', 'IPv6', 'ipv6'
          self[:start_addr] = PacketGen::Header::IPv6::Addr.new unless self[:start_addr].is_a?(PacketGen::Header::IPv6::Addr)
          self[:end_addr] = PacketGen::Header::IPv6::Addr.new unless self[:end_addr].is_a?(PacketGen::Header::IPv6::Addr)
        else
          raise ArgumentError, "unknown type #{type}"
        end
      end

      def select_addr(options)
        if options[:type]
          select_addr_from_type options[:type]
        elsif options[:start_addr]
          ipv4 = IPAddr.new(options[:start_addr]).ipv4?
          self.type = ipv4 ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE
        elsif options[:end_addr]
          ipv4 = IPAddr.new(options[:end_addr]).ipv4?
          self.type = ipv4 ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE
        end
      end
    end

    # Set of {TrafficSelector}, used by {TSi} and {TSr}.
    # @author Sylvain Daubert
    class TrafficSelectors < BinStruct::Array
      set_of TrafficSelector
    end

    # This class handles Traffic Selector - Initiator payloads, denoted TSi.
    #
    # A TSi payload consists of the IKE generic payload Plugin (see {Payload})
    # and some specific fields:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Number of TSs |                 RESERVED                      |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                       <Traffic Selectors>                     ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # These specific fields are:
    # * {#num_ts},
    # * {#rsv1},
    # * {#rsv2},
    # * and {#traffic_selectors}.
    #
    # == Create a TSi payload
    #  # Create a IKE packet with a TSi payload
    #  pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::TSi')
    #  # add a traffic selector to this payload
    #  pkt.ike_tsi.traffic_selectors << { protocol: 'tcp', ports: 1..1024, start_addr: '20.0.0.1', end_addr: '21.255.255.254' }
    #  # add another traffic selector (IPv6, all protocols)
    #  pkt.ike_tsi.traffic_selectors << { start_addr: '2001::1', end_addr: '200a:ffff:ffff:ffff:ffff:ffff:ffff:ffff' }
    # @author Sylvain Daubert
    class TSi < Payload
      # Payload type number
      PAYLOAD_TYPE = 44

      remove_attr :content

      # @!attribute num_ts
      #   8-bit Number of TSs
      #   @return [Integer]
      define_attr_before :body, :num_ts, BinStruct::Int8
      # @!attribute rsv
      #   24-bit RESERVED field
      #   @return [Integer]
      define_attr_before :body, :rsv, BinStruct::Int24

      # @!attribute traffic_selectors
      #  Set of {TrafficSelector}
      #  @return {TrafficSelectors}
      define_attr_before :body, :traffic_selectors, TrafficSelectors,
                         builder: ->(h, t) { t.new(counter: h[:num_ts]) }
      alias selectors traffic_selectors

      # Compute length and set {#length} field
      # @return [Integer] new length
      def calc_length
        selectors.each(&:calc_length)
        super
      end
    end

    class TSr < TSi
      # Payload type number
      PAYLOAD_TYPE = 45
    end
  end

  PacketGen::Header.add_class IKE::TSi
  PacketGen::Header.add_class IKE::TSr
end
