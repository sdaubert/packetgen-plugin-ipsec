# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

# frozen_string_literal: true

module PacketGen::Plugin
  class IKE
    # PacketGen::Header::Base class for IKE payloads. This class may also be used for unknown payloads.
    #
    # This class handles generic IKE payload Plugin:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # to which a {#content} field is added to handle content of unknown payload types.
    # @author Sylvain Daubert
    class Payload < PacketGen::Header::Base
      # Give protocol name
      # @return [String]
      def self.protocol_name
        return @protocol_name if defined? @protocol_name

        basename = to_s.sub(/.*::/, '')
        @protocol_name = "IKE::#{basename}"
      end

      # @!attribute next
      #  8-bit next payload
      #  @return [Integer]
      define_attr :next, BinStruct::Int8
      # @!attribute flags
      #  8-bit flags
      #  @return [Integer]
      # @!attribute critical
      #  critical flag
      #  @return [Boolean]
      # @!attribute hreserved
      #  reserved part of {#flags} field
      #  @return [Integer]
      define_bit_attr :flags, critical: 1, hreserved: 7
      # @!attribute length
      #  16-bit payload total length, including generic payload Plugin
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute content
      #  Payload content. Depends on payload. Variable length.
      #  @return [String]
      define_attr :content, BinStruct::String, builder: ->(h, t) { t.new(length_from: -> { h.length - h.offset_of(:content) }) }

      # Defining a body permits using Packet#parse to parse next IKE payloads.
      define_attr :body, BinStruct::String

      def initialize(options={})
        super
        if options[:content]
          self[:content] = BinStruct::String.new
          self[:content].read options[:content]
        end
        calc_length unless options[:length]
      end

      # Compute length and set {#length} field
      # @return [Integer] new length
      def calc_length
        # Here, #body is next payload, so body size should not be taken in
        # account (payload's real body is #content).
        self.length = sz - self[:body].sz
      end
    end
  end

  PacketGen::Header.add_class IKE::Payload
end

require_relative 'sa'
require_relative 'ke'
require_relative 'nonce'
require_relative 'notify'
require_relative 'sk'
require_relative 'id'
require_relative 'cert'
require_relative 'certreq'
require_relative 'auth'
require_relative 'ts'
require_relative 'vendor_id'

module PacketGen::Plugin # rubocop:disable Metrics/ModuleLength
  IKE.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::Payload.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::KE.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::Notify.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::SK.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::IDi.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::IDr.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::Cert.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::Auth.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::TSi.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::TSr.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::SA, next: IKE::SA::PAYLOAD_TYPE

  IKE.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::Payload.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::SA.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::Notify.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::SK.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::IDi.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::IDr.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::Cert.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::Auth.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::TSi.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::TSr.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::KE, next: IKE::KE::PAYLOAD_TYPE

  IKE.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::Payload.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::SA.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::KE.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::Notify.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::SK.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::IDi.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::IDr.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::Cert.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::Auth.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::TSi.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::TSr.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::Nonce, next: IKE::Nonce::PAYLOAD_TYPE

  IKE.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::Payload.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::SA.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::KE.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::Notify.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::SK.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::IDi.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::IDr.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::Cert.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::Auth.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::TSi.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::TSr.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::Notify, next: IKE::Notify::PAYLOAD_TYPE

  IKE.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::Payload.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::SA.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::KE.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::Notify.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::IDi.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::IDr.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::Cert.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::Auth.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::TSi.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::TSr.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::SK, next: IKE::SK::PAYLOAD_TYPE

  IKE.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::Payload.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::SA.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::KE.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::Notify.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::SK.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::IDr.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::Cert.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::Auth.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::TSi.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::TSr.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::IDi, next: IKE::IDi::PAYLOAD_TYPE

  IKE.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::Payload.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::SA.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::KE.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::Notify.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::SK.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::IDi.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::Cert.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::Auth.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::TSi.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::TSr.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::IDr, next: IKE::IDr::PAYLOAD_TYPE

  IKE.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::Payload.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::SA.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::KE.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::Notify.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::SK.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::IDi.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::IDr.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::Auth.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::TSi.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::TSr.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::Cert, next: IKE::Cert::PAYLOAD_TYPE

  IKE.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::Payload.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::SA.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::KE.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::Notify.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::SK.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::IDi.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::IDr.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::Cert.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::Auth.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::TSi.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::TSr.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::CertReq, next: IKE::CertReq::PAYLOAD_TYPE

  IKE.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::Payload.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::SA.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::KE.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::Notify.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::SK.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::IDi.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::IDr.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::Cert.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::TSi.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::TSr.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::Auth, next: IKE::Auth::PAYLOAD_TYPE

  IKE.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::Payload.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::SA.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::KE.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::Notify.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::SK.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::IDi.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::IDr.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::Cert.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::Auth.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::TSr.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::TSi, next: IKE::TSi::PAYLOAD_TYPE

  IKE.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::Payload.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::SA.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::KE.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::Notify.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::SK.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::IDi.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::IDr.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::Cert.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::Auth.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::TSi.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE
  IKE::VendorID.bind IKE::TSr, next: IKE::TSr::PAYLOAD_TYPE

  IKE.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::Payload.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::SA.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::KE.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::Nonce.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::Notify.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::SK.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::IDi.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::IDr.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::Cert.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::CertReq.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::Auth.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::TSi.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE
  IKE::TSr.bind IKE::VendorID, next: IKE::VendorID::PAYLOAD_TYPE

  # Last defined. To be used as default if no other may be parsed.
  IKE::SA.bind IKE::Payload, next: lambda(&:positive?)
  IKE::KE.bind IKE::Payload, next: lambda(&:positive?)
  IKE::Nonce.bind IKE::Payload, next: lambda(&:positive?)
  IKE::Notify.bind IKE::Payload, next: lambda(&:positive?)
  IKE::SK.bind IKE::Payload, next: lambda(&:positive?)
  IKE::IDi.bind IKE::Payload, next: lambda(&:positive?)
  IKE::IDr.bind IKE::Payload, next: lambda(&:positive?)
  IKE::Cert.bind IKE::Payload, next: lambda(&:positive?)
  IKE::CertReq.bind IKE::Payload, next: lambda(&:positive?)
  IKE::Auth.bind IKE::Payload, next: lambda(&:positive?)
  IKE::TSi.bind IKE::Payload, next: lambda(&:positive?)
  IKE::TSr.bind IKE::Payload, next: lambda(&:positive?)
  IKE::VendorID.bind IKE::Payload, next: lambda(&:positive?)
  IKE.bind IKE::Payload, next: lambda(&:positive?)
  IKE::Payload.bind IKE::Payload, next: lambda(&:positive?)
end
