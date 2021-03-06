# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # This class handles encrypted payloads, denoted SK.
    #
    # The encrypted payload contains other payloads in encrypted form.
    # The Encrypted payload consists of the IKE generic payload Plugin followed
    # by individual fields as follows:
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                     Initialization Vector                     |
    #   |         (length is block size for encryption algorithm)       |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   ~                    Encrypted IKE Payloads                     ~
    #   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |               |             Padding (0-255 octets)            |
    #   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
    #   |                                               |  Pad Length   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   ~                    Integrity Checksum Data                    ~
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # Encrypted payloads are set in {#content} field, as a {PacketGen::Types::String}.
    # All others fields are only set when decrypting a previously read SK
    # payload. They also may be set manually to encrypt IKE payloads.
    #
    # == Read and decrypt a SK payload
    #   # Read a IKE packet
    #   pkt = PacketGen.read(str)
    #   # decrypt SK payload
    #   cipher = OpenSSL::Cipher.new('aes-128-ctr')
    #   cipher.decrypt
    #   cipher_key = aes_key
    #   hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)
    #   pkt.ike_sk.decrypt! cipher, intmode: hmac, icv_length: 16   # => true if authentication is verified
    #   pkt.ike_sk.body       # => kind of PacketGen::Plugin::IKE::Payload
    #
    # == Set and encrypt a SK payload
    #   # Create a IKE packet
    #   pkt = PacketGen.gen('IP').add('IP').add('UDP').add('IKE', init_spi: 0x123456789, resp_spi: 0x987654321, type: 'IKE_AUTH', message_id: 1)
    #   # Add SK payload
    #   pkt.add('IKE::SK', icv_length: 16)
    #   # Add others unencrypted payloads
    #   pkt.add('IKE::IDi').add('IKE::Auth').add('IKE::SA').add('IKE::TSi').add('IKE::TSr')
    #   # encrypt SK payload
    #   cipher = OpenSSL::Cipher.new('aes-128-ctr')
    #   cipher.encrypt
    #   cipher_key = aes_key
    #   hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)
    #   pkt.ike_sk.encrypt! cipher, iv, salt: salt, intmode: hmac
    #   pkt.ike_sk.body       # => String
    #   pkt.calc_length
    #
    # @author Sylvain Daubert
    class SK < Payload
      include Crypto

      # Payload type number
      PAYLOAD_TYPE = 46

      # ICV (Integrity Check Value) length
      # @return [Integer]
      attr_accessor :icv_length

      # @param [Hash] options
      # @option options [Integer] :icv_length ICV length
      def initialize(options={})
        @icv_length = options[:icv_length] || 0
        super
      end

      # Decrypt in-place SK payload.
      # @param [OpenSSL::Cipher] cipher keyed cipher
      #   This cipher is confidentiality-only one, or AEAD one. To use a second
      #   cipher to add integrity, use +:intmode+ option.
      # @param [Hash] options
      # @option options [Boolean] :parse parse deciphered payload to retrieve
      #   Plugins (default: +true+)
      # @option options [Fixnum] :icv_length ICV length for captured packets,
      #   or read from PCapNG files
      # @option options [String] :salt salt value for CTR and GCM modes
      # @option options [OpenSSL::HMAC] :intmode integrity mode to use with a
      #   confidentiality-only cipher. Only HMAC are supported.
      # @return [Boolean] +true+ if SK payload is authenticated
      def decrypt!(cipher, options={})
        opt = { salt: '', parse: true }.merge!(options)

        set_crypto cipher, opt[:intmode]

        case confidentiality_mode
        when 'gcm'
          iv = self[:content].slice!(0, 8)
          real_iv = force_binary(opt[:salt]) + iv
        when 'cbc'
          cipher.padding = 0
          real_iv = iv = self[:content].slice!(0, 16)
        when 'ctr'
          iv = self[:content].slice!(0, 8)
          real_iv = force_binary(opt[:salt]) + iv + [1].pack('N')
        else
          real_iv = iv = self[:content].slice!(0, 16)
        end
        cipher.iv = real_iv

        if authenticated?
          if @icv_length.zero?
            @icv_length = opt[:icv_length].to_i if opt[:icv_length]
            raise PacketGen::ParseError, 'unknown ICV size' if @icv_length.zero?
          end
          icv = self[:content].slice!(-@icv_length, @icv_length)
        end

        authenticate_if_needed iv, icv
        private_decrypt opt
      end

      # Encrypt in-place SK payload.
      # @param [OpenSSL::Cipher] cipher keyed cipher
      #   This cipher is confidentiality-only one, or AEAD one. To use a second
      #   cipher to add integrity, use +:intmode+ option.
      # @param [String] iv IV to encipher SK payload content
      #   * CTR and GCM modes: +iv+ is 8-bytes long.
      # @param [Hash] options
      # @option options [Fixnum] :icv_length ICV length for captured packets,
      #   or read from PCapNG files
      # @option options [String] :salt salt value for CTR and GCM modes
      # @option options [Fixnum] :pad_length set a padding length
      # @option options [String] :padding set a padding. No check with
      #   +:pad_length+ is made. If +:pad_length+ is not set, +:padding+
      #   length is shortened to correct padding length
      # @option options [OpenSSL::HMAC] :intmode integrity mode to use with a
      #   confidentiality-only cipher. Only HMAC are supported.
      # @return [self]
      def encrypt!(cipher, iv, options={})
        opt = { salt: '' }.merge!(options)

        set_crypto cipher, opt[:intmode]

        real_iv = force_binary(opt[:salt]) + force_binary(iv)
        real_iv += [1].pack('N') if confidentiality_mode == 'ctr'
        cipher.iv = real_iv

        authenticate_if_needed iv

        if opt[:pad_length]
          pad_length = opt[:pad_length]
          padding = force_binary(opt[:padding] || ([0] * pad_length).pack('C*'))
        else
          pad_length = cipher.block_size
          pad_length = 16 if cipher.block_size == 1 # Some AES mode returns 1...
          pad_length -= (self[:body].sz + iv.size + 1) % cipher.block_size
          pad_length = 0 if pad_length == 16
          padding = force_binary(opt[:padding] || ([0] * pad_length).pack('C*'))
          padding = padding[0, pad_length]
        end
        msg = self[:body].to_s + padding + PacketGen::Types::Int8.new(pad_length).to_s
        encrypted_msg = encipher(msg)
        cipher.final # message is already padded. No need for mode padding

        if authenticated?
          @icv_length = opt[:icv_length] if opt[:icv_length]
          encrypted_msg << if @conf.authenticated?
                             @conf.auth_tag[0, @icv_length]
                           else
                             @intg.digest[0, @icv_length]
                           end
        end
        self[:content].read(iv + encrypted_msg)

        # Remove plain payloads
        self[:body] = PacketGen::Types::String.new

        # Remove enciphered payloads from packet
        id = header_id(self)
        if id < packet.headers.size - 1
          (packet.headers.size - 1).downto(id + 1) do |index|
            packet.headers.delete_at index
          end
        end

        self.calc_length
        self
      end

      private

      def authenticate_if_needed(iv, icv=nil)
        if @conf.authenticated?
          @conf.auth_tag = icv if icv
          @conf.auth_data = get_ad
        elsif @intg
          @intg.reset
          @intg.update get_ad
          @intg.update iv
          @icv = icv
        else
          @icv = nil
        end
      end

      # From RFC 7206, §5.1: The associated data MUST consist of the partial
      # contents of the IKEv2 message, starting from the first octet of the
      # Fixed IKE Plugin through the last octet of the Payload Plugin of the
      # Encrypted Payload (i.e., the fourth octet of the Encrypted Payload).
      def get_ad
        str = packet.ike.to_s[0, IKE.new.sz]
        current_payload = packet.ike[:body]
        until current_payload.is_a? SK
          str << current_payload.to_s[0, current_payload.to_s.length]
          current_payload = current_payload[:body]
        end
        str << self.to_s[0, SK.new.sz]
      end

      def private_decrypt(options)
        # decrypt
        plain_msg = decipher(content.to_s)
        # Remove cipher text
        self[:content].read ''

        # check authentication tag
        if authenticated?
          return false unless authenticate!
        end

        # remove padding
        pad_len = PacketGen::Types::Int8.new.read(plain_msg[-1]).to_i
        payloads = plain_msg[0, plain_msg.size - 1 - pad_len]

        # parse IKE payloads
        if options[:parse]
          klass = IKE.constants.select do |c|
            cst = IKE.const_get(c)
            cst.is_a?(Class) && (cst < Payload) && (cst::PAYLOAD_TYPE == self.next)
          end
          klass = klass.nil? ? Payload : IKE.const_get(klass.first)
          firsth = klass.protocol_name
          pkt = PacketGen::Packet.parse(payloads, first_header: firsth)
          packet.encapsulate(pkt, parsing: true) unless pkt.nil?
        else
          self[:body].read payloads
        end

        true
      end
    end
  end

  PacketGen::Header.add_class IKE::SK
end
