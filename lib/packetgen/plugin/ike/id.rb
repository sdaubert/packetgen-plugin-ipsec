# coding: utf-8
# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class IKE
    # This class handles Identification - Initiator payloads, denoted IDi
    # (see RFC 7296, §3.5).
    #
    # A ID payload consists of the IKE generic payload Plugin (see {Payload})
    # and some specific fields:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |   ID Type     |                 RESERVED                      |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                   Identification Data                         ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # These specific fields are:
    # * {#type} (ID type),
    # * {#reserved},
    # * and {#content} (Identification Data).
    #
    # == Create a IDi payload
    #   # Create a IKE packet with a IDi payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::IDi', type: 'FQDN')
    #   pkt.ike_idi.content.read 'fqdn.example.org'
    #   pkt.calc_length
    # @author Sylvain Daubert
    class IDi < Payload
      # Payload type number
      PAYLOAD_TYPE = 35

      # ID types
      TYPES = {
        'IPV4_ADDR' => 1,
        'FQDN' => 2,
        'RFC822_ADDR' => 3,
        'IPV6_ADDR' => 5,
        'DER_ASN1_DN' => 9,
        'DER_ASN1_GN' => 10,
        'KEY_ID' => 11
      }.freeze

      # @attribute [r] type
      #   8-bit ID type
      #   @return [Integer]
      define_attr_before :content, :type, BinStruct::Int8Enum, enum: TYPES
      # @attribute reserved
      #   24-bit reserved field
      #   @return [Integer]
      define_attr_before :content, :reserved, BinStruct::Int24

      # Get ID type name
      # @return [String]
      def human_type
        self[:type].to_human
      end

      # Get human readable content, from {#type}
      # @return [String]
      def human_content
        case type
        when TYPES['IPV4_ADDR'], TYPES['IPV6_ADDR']
          IPAddr.ntop(content)
        when TYPES['DER_ASN1_DN'], TYPES['DER_ASN1_GN']
          OpenSSL::X509::Name.new(content).to_s
        else
          content.inspect
        end
      end
    end

    # This class handles Identification - Responder payloads, denoted IDr.
    # See {IDi}.
    #
    # == Create a IDr payload
    #   # Create a IKE packet with a IDr payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::IDr', type: 'FQDN')
    #   pkt.ike_idr.content.read 'fqdn.example.org'
    # @author Sylvain Daubert
    class IDr < IDi
      # Payload type number
      PAYLOAD_TYPE = 36
    end
  end

  PacketGen::Header.add_class IKE::IDi
  PacketGen::Header.add_class IKE::IDr
end
