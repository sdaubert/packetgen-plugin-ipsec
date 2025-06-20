# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # This class handles Nonce payloads, as defined in RFC 7296 §3.9.
    #
    # A Nonce payload contains a generic payload Plugin (see {Payload}) and
    # data field (type {BinStruct::String}):
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                            Nonce Data                         ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # == Create a Nonce payload
    #   # Create a IKE packet with a Nonce payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
    #   pkt.add('IKE::Nonce', data: "abcdefgh")
    #   pkt.calc_length
    # @author Sylvain Daubert
    class Nonce < Payload
      # Payload type number
      PAYLOAD_TYPE = 40
    end
  end

  PacketGen::Header.add_class IKE::Nonce
end
