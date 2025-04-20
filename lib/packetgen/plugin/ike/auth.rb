# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # This class handles Authentication payloads.
    #
    # A AUTH payload consists of the IKE generic payload Plugin (see {Payload})
    # and some specific fields:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Auth Method   |                RESERVED                       |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                      Authentication Data                      ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # These specific fields are:
    # * {#type} (ID type),
    # * {#reserved},
    # * and {#content} (Identification Data).
    #
    # == Create a KE payload
    #   # create a IKE packet with a Auth payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::Auth', auth_method: 'SHARED_KEY')
    #   pkt.calc_length
    # @author Sylvain Daubert
    class Auth < Payload
      # Payload type number
      PAYLOAD_TYPE = 39

      # Authentication methods
      METHODS = {
        'RSA_SIGNATURE' => 1,
        'SHARED_KEY' => 2,
        'DSA_SIGNATURE' => 3,
        'ECDSA256' => 9,
        'ECDSA384' => 10,
        'ECDSA512' => 11,
        'PASSWORD' => 12,
        'NULL' => 13,
        'DIGITAL_SIGNATURE' => 14
      }.freeze

      # @attribute [r] auth_method
      #   8-bit Auth Method
      #   @return [Integer]
      define_attr_before :content, :auth_method, BinStruct::Int8Enum, enum: METHODS
      # @attribute reserved
      #   24-bit reserved field
      #   @return [Integer]
      define_attr_before :content, :reserved, BinStruct::Int24

      # Check authentication (see RFC 7296 §2.15)
      # @param [Packet] init_msg first IKE message sent by peer
      # @param [String] nonce my nonce, sent in first message
      # @param [String] sk_p secret key used to compute prf(SK_px, IDx')
      # @param [Integer] prf PRF type to use (see {Transform}+::PRF_*+ constants)
      # @param [String] shared_secret shared secret to use as PSK (shared secret
      #    method only)
      # @param [OpenSSL::X509::Certificate] cert certificate to check AUTH signature,
      #   if not embedded in IKE message
      # @return [Boolean]
      # @note For now, only NULL, SHARED_KEY and RSA, DSA and ECDSA signatures are
      #   supported.
      # @note For certificates, only check AUTH authenticity with given (or guessed
      #   from packet) certificate, but certificate chain is not verified.
      def check?(init_msg: nil, nonce: '', sk_p: '', prf: 1, shared_secret: '', # rubocop:disable Metrics/ParameterLists
                 cert: nil)
        raise TypeError, 'init_msg should be a Packet' unless init_msg.is_a?(PacketGen::Packet)

        signed_octets = build_signed_octets(init_msg, nonce, sk_p, prf)
        case auth_method
        when METHODS['SHARED_KEY']
          check_shared_key?(shared_secret, signed_octets)
        when METHODS['RSA_SIGNATURE'], METHODS['ECDSA256'], METHODS['ECDSA384'],
             METHODS['ECDSA512']
          check_signature?(cert, signed_octets)
        when METHOD_NULL
          true
        else
          raise NotImplementedError, "unsupported auth method #{human_auth_method}"
        end
      end

      # Get authentication method name
      # @return [String]
      def human_auth_method
        self[:auth_method].to_human
      end

      private

      def build_signed_octets(init_msg, nonce, sk_p, prf)
        signed_octets = init_msg.ike.to_s
        signed_octets << nonce
        id = packet.ike.flag_i? ? packet.ike_idi : packet.ike_idr
        signed_octets << prf(prf, sk_p, id.to_s[4, id.length - 4])
      end

      def prf(type, key, msg)
        case type
        when Transform::PRF_HMAC_MD5, Transform::PRF_HMAC_SHA1,
             Transform::PRF_HMAC_SHA2_256, Transform::PRF_HMAC_SHA2_384,
             Transform::PRF_HMAC_SHA2_512
          digestname = Transform.constants.grep(/PRF_/)
                                .detect { |c| Transform.const_get(c) == type }
                                .to_s.sub(/^PRF_HMAC_/, '').sub(/2_/, '')
          digest = OpenSSL::Digest.const_get(digestname).new
        else
          raise NotImplementedError, 'for now, only HMAC-based PRF are supported'
        end
        hmac = OpenSSL::HMAC.new(key, digest)
        hmac << msg
        hmac.digest
      end

      def check_shared_key?(shared_secret, signed_octets)
        auth = prf(prf(shared_secret, 'Key Pad for IKEv2'), signed_octets)
        auth == content
      end

      def check_signature?(cert, signed_octets)
        if packet.ike_cert
          # FIXME: Expect a ENCODING_X509_CERT_SIG
          #        Others types not supported for now...
          cert = OpenSSL::X509::Certificate.new(packet.ike_cert.content)
        elsif cert.nil?
          raise CryptoError, 'a certificate should be provided'
        end

        text = cert.to_text
        digest = build_digest_object(text)
        signature = format_signature(cert.public_key, content.to_s)
        cert.public_key.verify(digest, signature, signed_octets)
      end

      def build_digest_object(text)
        m = text.match(/Public Key Algorithm: ([a-zA-Z0-9-]+)/)
        case m[1]
        when 'id-ecPublicKey'
          m2 = text.match(/Public-Key: \((\d+) bit\)/)
          case m2[1]
          when '256', '384'
            OpenSSL::Digest.new("SHA#{m2[1]}")
          when '521'
            OpenSSL::Digest.new(SHA512)
          end
        when /sha([235]\d+)/
          OpenSSL::Digest.new("SHA#{$1}")
        when /sha1/, 'rsaEncryption'
          OpenSSL::Digest.new('SHA1')
        end
      end

      def format_signature(pkey, sig)
        if pkey.is_a?(OpenSSL::PKey::EC)
          # PKey::EC need a signature as a DER string representing a sequence of
          # 2 integers: r and s
          r = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(sig[0, sig.size / 2], 2).to_i)
          s = OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(sig[sig.size / 2,
                                                             sig.size / 2], 2).to_i)
          OpenSSL::ASN1::Sequence.new([r, s]).to_der
        else
          sig
        end
      end
    end
  end
end
