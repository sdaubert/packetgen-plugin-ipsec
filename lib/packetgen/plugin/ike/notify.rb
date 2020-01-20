# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # This class handles Notify payloads, as defined in RFC 7296 §3.10.
    #
    # A Notify payload contains a generic payload Plugin (see {Payload}) and
    # some specific fields:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |  Protocol ID  |   SPI Size    |      Notify Message Type      |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                Security Parameter Index (SPI)                 ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                       Notification Data                       ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # These specific fields are:
    # * {#protocol} (type {PacketGen::Types::Int8}),
    # * {#spi_size} (type {PacketGen::Types::Int8}),
    # * {#message_type} (type {PacketGen::Types::Int16}),
    # * {#spi} (type {PacketGen::Types::String}),
    # * {#content} (type {PacketGen::Types::String}).
    #
    # == Create a Notify payload
    #   # Create a IKE packet with a Notify payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::Notify', protocol: 'IKE', type: 'INVALID_SYNTAX')
    #   pkt.ike_notify.spi      # => ""
    #   pkt.ike_notify.content  # => ""
    #   pkt.calc_length
    # == Create a Notify payload with a SPI
    #   # Create a IKE packet with a Notify payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::Notify', protocol: 'ESP', spi_size: 4, type: 'INVALID_SYNTAX')
    #   pkt.ike_notify.spi.read PacketGen::Types::Int32.new(0x12345678).to_s
    #   pkt.calc_length
    #   @author Sylvain Daubert
    class Notify < Payload
      # Payload type number
      PAYLOAD_TYPE = 41

      # Message types
      TYPES = {
        'UNSUPPORTED_CRITICAL_PAYLOAD' => 1,
        'INVALID_IKE_SPI' => 4,
        'INVALID_MAJOR_VERSION' => 5,
        'INVALID_SYNTAX' => 7,
        'INVALID_MESSAGE_ID' => 9,
        'INVALID_SPI' => 11,
        'NO_PROPOSAL_CHOSEN' => 14,
        'INVALID_KE_PAYLOAD' => 17,
        'AUTHENTICATION_FAILED' => 24,
        'SINGLE_PAIR_REQUIRED' => 34,
        'NO_ADDITIONAL_SAS' => 35,
        'INTERNAL_ADDRESS_FAILURE' => 36,
        'FAILED_CP_REQUIRED' => 37,
        'TS_UNACCEPTABLE' => 38,
        'INVALID_SELECTORS' => 39,
        'TEMPORARY_FAILURE' => 43,
        'CHILD_SA_NOT_FOUND' => 44,
        'INITIAL_CONTACT' => 16_384,
        'SET_WINDOW_SIZE' => 16_385,
        'ADDITIONAL_TS_POSSIBLE' => 16_386,
        'IPCOMP_SUPPORTED' => 16_387,
        'NAT_DETECTION_SOURCE_IP' => 16_388,
        'NAT_DETECTION_DESTINATION_IP' => 16_389,
        'COOKIE' => 16_390,
        'USE_TRANSPORT_MODE' => 16_391,
        'HTTP_CERT_LOOKUP_SUPPORTED' => 16_392,
        'REKEY_SA' => 16_393,
        'ESP_TFC_PADDING_NOT_SUPPORTED' => 16_394,
        'NON_FIRST_FRAGMENTS_ALSO' => 16_395,
      }.freeze

      # @!attribute [r] protocol
      #  8-bit protocol ID. If this notification concerns an existing
      #  SA whose SPI is given in the SPI field, this field indicates the
      #  type of that SA.  For notifications concerning Child SAs, this
      #  field MUST contain either (2) to indicate AH or (3) to indicate
      #  ESP.  Of the notifications defined in this document, the SPI is
      #  included only with INVALID_SELECTORS, REKEY_SA, and
      #  CHILD_SA_NOT_FOUND.  If the SPI field is empty, this field MUST be
      #  sent as zero and MUST be ignored on receipt.
      #  @return [Integer]
      define_field_before :content, :protocol, PacketGen::Types::Int8Enum, enum: PROTOCOLS
      # @!attribute spi_size
      #  8-bit SPI size. Give size of SPI field. Length in octets of the SPI as
      #  defined by the IPsec protocol ID or zero if no SPI is applicable. For a
      #  notification concerning the IKE SA, the SPI Size MUST be zero and
      #  the field must be empty.Set to 0 for an initial IKE SA
      #  negotiation, as SPI is obtained from outer Plugin.
      #  @return [Integer]
      define_field_before :content, :spi_size, PacketGen::Types::Int8, default: 0
      # @!attribute message_type
      #  16-bit notify message type. Specifies the type of notification message.
      #  @return [Integer]
      define_field_before :content, :message_type, PacketGen::Types::Int16Enum, enum: TYPES, default: 0
      # @!attribute spi
      #   the sending entity's SPI. When the {#spi_size} field is zero,
      #   this field is not present in the proposal.
      #   @return [String]
      define_field_before :content, :spi, PacketGen::Types::String,
                          builder: ->(h, t) { t.new(length_from: h[:spi_size]) }

      alias type message_type

      def initialize(options={})
        options[:spi_size] = options[:spi].size if options[:spi] && options[:spi_size].nil?
        super
        self.protocol = options[:protocol] if options[:protocol]
        self.message_type = options[:message_type] if options[:message_type]
        self.message_type = options[:type] if options[:type]
      end

      alias type= message_type=

      # Get protocol name
      # @return [String]
      def human_protocol
        self[:protocol].to_human
      end

      # Get message type name
      # @return [String]
      def human_message_type
        self[:message_type].to_human
      end
      alias human_type human_message_type

      # @return [String]
      def inspect
        super do |attr|
          next unless attr == :protocol

          str = PacketGen::Inspect.shift_level
          str << PacketGen::Inspect::FMT_ATTR % [self[attr].class.to_s.sub(/.*::/, ''), attr,
                                      human_protocol]
        end
      end
    end
  end

  PacketGen::Header.add_class IKE::Notify
end
