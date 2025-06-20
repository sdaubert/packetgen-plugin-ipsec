# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # This class handles Key Exchange payloads, as defined in RFC 7296 §3.4
    #
    # A KE payload contains a generic payload Plugin (see {Payload}) and some
    # specific fields:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |   Diffie-Hellman Group Num    |           RESERVED            |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                       Key Exchange Data                       ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # These specific fields are:
    # * {#group_num} (type {BinStruct::Int16}),
    # * {#reserved} (type {BinStruct::Int16}),
    # * and {#content} (type {BinStruct::String}).
    #
    # == Create a KE payload
    #   # Create a IKE packet with a KE payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE')
    #   # group name is taken from Transform::DH_* constants
    #   pkt.add('IKE::KE', group: 'MODP4096')
    #   # group number may also be used
    #   pkt.ike_ke.group = 1
    #   pkt.calc_length
    # @author Sylvain Daubert
    class KE < Payload
      # Payload type number
      PAYLOAD_TYPE = 34

      # @!attribute group_num
      #  16-bit DH group number
      #  @return [Integer]
      define_attr_before :content, :group_num, BinStruct::Int16
      # @!attribute reserved
      #  16-bit reserved field
      #  @return [Integer]
      define_attr_before :content, :reserved, BinStruct::Int16, default: 0

      def initialize(options={})
        super
        self.group = options[:group] if options[:group]
      end

      # Set group
      # @param [Integer,String] value may be a String taken from
      #   {Transform}+::DH_*+ constant names.
      # @return [Integer]
      def group=(value)
        group = case value
                when Integer
                  value
                else
                  cname = "DH_#{value}"
                  Transform.const_defined?(cname) ? Transform.const_get(cname) : nil
                end
        raise ArgumentError, "unknown group #{value.inspect}" unless group

        self[:group_num].value = group
      end
    end
  end

  PacketGen::Header.add_class IKE::KE
end
