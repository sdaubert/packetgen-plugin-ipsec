# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

require_relative 'crypto'

# rubocop:disable Metrics/ClassLength

module PacketGen::Plugin
  # A ESP header consists of:
  # * a Security Parameters Index (#{spi}, {BinStruct::Int32} type),
  # * a Sequence Number ({#sn}, +Int32+ type),
  # * a {#body} (variable length),
  # * an optional TFC padding ({#tfc}, variable length),
  # * an optional {#padding} (to align ESP on 32-bit boundary, variable length),
  # * a {#pad_length} ({BinStruct::Int8}),
  # * a Next header field ({#next}, +Int8+),
  # * and an optional Integrity Check Value ({#icv}, variable length).
  #
  # == Create an ESP header
  #  # standalone
  #  esp = PacketGen::Plugin::ESP.new
  #  # in a packet
  #  pkt = PacketGen.gen('IP').add('ESP')
  #  # access to ESP header
  #  pkt.esp   # => PacketGen::Plugin::ESP
  #
  # == Examples
  # === Create an enciphered UDP packet (ESP transport mode), using CBC mode
  #  icmp = PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.2.1').
  #                   add('ESP', spi: 0xff456e01, sn: 12345678).
  #                   add('UDP', dport: 4567, sport: 45362, body 'abcdef')
  #  cipher = OpenSSL::Cipher.new('aes-128-cbc')
  #  cipher.encrypt
  #  cipher.key = 16bytes_key
  #  iv = 16bytes_iv
  #  esp.esp.encrypt! cipher, iv
  #
  # === Create a ESP packet tunneling a UDP one, using GCM combined mode
  #  # create inner UDP packet
  #  icmp = PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.2.1').
  #                   add('UDP', dport: 4567, sport: 45362, body 'abcdef')
  #
  #  # create outer ESP packet
  #  esp = PacketGen.gen('IP', src '198.76.54.32', dst: '1.2.3.4').add('ESP')
  #  esp.esp.spi = 0x87654321
  #  esp.esp.sn  = 0x123
  #  esp.esp.icv_length = 16
  #  # encapsulate ICMP packet in ESP one
  #  esp.encapsulate icmp
  #
  #  # encrypt ESP payload
  #  cipher = OpenSSL::Cipher.new('aes-128-gcm')
  #  cipher.encrypt
  #  cipher.key = 16bytes_key
  #  iv = 8bytes_iv
  #  esp.esp.encrypt! cipher, iv, salt: 4bytes_gcm_salt
  #
  # === Decrypt a ESP packet using CBC mode and HMAC-SHA-256
  #  cipher = OpenSSL::Cipher.new('aes-128-cbc')
  #  cipher.decrypt
  #  cipher.key = 16bytes_key
  #
  #  hmac = OpenSSL::HMAC.new(hmac_key, OpenSSL::Digest::SHA256.new)
  #
  #  pkt.esp.decrypt! cipher, intmode: hmac    # => true if ICV check OK
  # @author Sylvain Daubert
  class ESP < PacketGen::Header::Base
    include Crypto

    # IP protocol number for ESP
    IP_PROTOCOL = 50

    # Well-known UDP port for ESP
    UDP_PORT = 4500

    # @!attribute spi
    #  32-bit Security Parameter Index
    #  @return [Integer]
    define_attr :spi, BinStruct::Int32
    # @!attribute sn
    #  32-bit Sequence Number
    #  @return [Integer]
    define_attr :sn, BinStruct::Int32
    # @!attribute body
    #  @return [BinStruct::String,PacketGen::Header::Base]
    define_attr :body, BinStruct::String
    # @!attribute tfc
    #  Traffic Flow Confidentiality padding
    #  @return [BinStruct::String,PacketGen::Header::Base]
    define_attr :tfc, BinStruct::String
    # @!attribute padding
    #  ESP padding
    #  @return [BinStruct::String,PacketGen::Header::Base]
    define_attr :padding, BinStruct::String
    # @!attribute pad_length
    #  8-bit padding length
    #  @return [Integer]
    define_attr :pad_length, BinStruct::Int8
    # @!attribute next
    #  8-bit next protocol value
    #  @return [Integer]
    define_attr :next, BinStruct::Int8
    # @!attribute icv
    #  Integrity Check Value
    #  @return [BinStruct::String,PacketGen::Header::Base]
    define_attr :icv, BinStruct::String

    # ICV (Integrity Check Value) length
    # @return [Integer]
    attr_accessor :icv_length

    # @param [Hash] options
    # @option options [Integer] :icv_length ICV length
    # @option options [Integer] :spi Security Parameters Index
    # @option options [Integer] :sn Sequence Number
    # @option options [::String] :body ESP payload data
    # @option options [::String] :tfc Traffic Flow Confidentiality, random padding
    #    up to MTU
    # @option options [::String] :padding ESP padding to align ESP on 32-bit
    #    boundary
    # @option options [Integer] :pad_length padding length
    # @option options [Integer] :next Next Header field
    # @option options [::String] :icv Integrity Check Value
    def initialize(options={})
      @icv_length = options[:icv_length] || 0
      super
    end

    # Read a ESP packet from string.
    #
    # {#padding} and {#tfc} are not set as they are enciphered (impossible
    # to guess their respective size). {#pad_length} and {#next} are also
    # enciphered.
    # @param [String] str
    # @return [self]
    def read(str)
      return self if str.nil?

      str = str.b
      self[:spi].read(str[0, 4])
      self[:sn].read(str[4, 4])
      self[:tfc].read('')
      self[:padding].read('')

      read_icv_dependent_fields(str[8..])
      read_icv(str)
      self
    end

    # Encrypt in-place ESP payload and trailer.
    #
    # This method removes all data from +tfc+ and +padding+ fields, as their
    # enciphered values are concatenated into +body+.
    #
    # It also removes headers under ESP from packet, as they are enciphered in
    # ESP body, and then are no more accessible.
    # @param [OpenSSL::Cipher] cipher keyed cipher.
    #   This cipher is confidentiality-only one, or AEAD one. To use a second
    #   cipher to add integrity, use +:intmode+ option.
    # @param [String] iv full IV for encryption
    #  * CTR and GCM modes: +iv+ is 8-bytes long.
    # @param [Hash] options
    # @option options [String] :salt salt value for CTR and GCM modes
    # @option options [Boolean] :tfc
    # @option options [Fixnum] :tfc_size ESP body size used for TFC
    #   (default 1444, max size for a tunneled IPv4/ESP packet).
    #   This is the maximum size for ESP packet (without IP header
    #   nor Eth one).
    # @option options [Fixnum] :esn 32 high-orber bits of ESN
    # @option options [Fixnum] :pad_length set a padding length
    # @option options [String] :padding set a padding. No check with
    #   +:pad_length+ is made. If +:pad_length+ is not set, +:padding+
    #   length is shortened to correct padding length
    # @option options [OpenSSL::HMAC] :intmode integrity mode to use with a
    #   confidentiality-only cipher. Only HMAC are supported.
    # @return [self]
    def encrypt!(cipher, iv, options={}) # rubocop:disable Naming/MethodParameterName
      opt = { salt: '', tfc_size: 1444 }.merge(options)

      set_crypto cipher, opt[:intmode]
      compute_iv_for_encrypting iv, opt[:salt]

      authenticate_esp_header_if_needed options, iv

      encrypt_set_pad_length
      encrypt_set_padding(opt)
      encrypt_body(opt, iv)

      set_esp_icv_if_needed
      remove_enciphered_packets

      self
    end

    # Decrypt in-place ESP payload and trailer.
    # @param [OpenSSL::Cipher] cipher keyed cipher
    #   This cipher is confidentiality-only one, or AEAD one. To use a second
    #   cipher to add integrity, use +:intmode+ option.
    # @param [Hash] options
    # @option options [Boolean] :parse parse deciphered payload to retrieve
    #   headers (default: +true+)
    # @option options [Fixnum] :icv_length ICV length for captured packets,
    #   or read from PCapNG files
    # @option options [String] :salt salt value for CTR and GCM modes
    # @option options [Fixnum] :esn 32 high-orber bits of ESN
    # @option options [OpenSSL::HMAC] :intmode integrity mode to use with a
    #   confidentiality-only cipher. Only HMAC are supported.
    # @return [Boolean] +true+ if ESP packet is authenticated
    def decrypt!(cipher, options={})
      opt = { salt: '', parse: true }.merge(options)

      set_crypto cipher, opt[:intmode]
      iv = compute_iv_for_decrypting(opt[:salt], self[:body])
      if authenticated? && (@icv_length.zero? || opt[:icv_length])
        check_icv_length(opt)
        decrypt_format_packet
      end
      authenticate_esp_header_if_needed options, iv, icv
      private_decrypt opt
    end

    private

    def read_icv_dependent_fields(str)
      body_end = -@icv_length - 2
      self[:body].read str[0...body_end]
      self[:pad_length].read str[body_end, 1]
      self[:next].read str[body_end + 1, 1]
    end

    def read_icv(str)
      self[:icv].read str[-@icv_length, @icv_length] if @icv_length
    end

    def get_auth_data(opt)
      ad = self[:spi].to_s
      if opt[:esn]
        @esn = BinStruct::Int32.new(value: opt[:esn])
        ad << @esn.to_s if @conf.authenticated?
      end
      ad << self[:sn].to_s
    end

    def authenticate_esp_header_if_needed(opt, iv, icv=nil) # rubocop:disable Naming/MethodParameterName
      if @conf.authenticated?
        @conf.auth_tag = icv if icv
        @conf.auth_data = get_auth_data(opt)
      elsif @intg
        @intg.reset
        @intg.update get_auth_data(opt)
        @intg.update iv
        @icv = icv
      else
        @icv = nil
      end
    end

    def encrypt_set_pad_length
      case confidentiality_mode
      when 'cbc'
        cipher_len = self[:body].sz + 2
        self.pad_length = (16 - (cipher_len % 16)) % 16
      else
        mod4 = to_s.size % 4
        self.pad_length = 4 - mod4 if mod4.positive?
      end
    end

    def encrypt_set_padding(opt)
      if opt[:pad_length]
        self.pad_length = opt[:pad_length]
        padding = opt[:padding] || (1..self.pad_length).to_a.pack('C*')
      else
        padding = opt[:padding] || (1..self.pad_length).to_a.pack('C*')
        padding = padding[0...self.pad_length]
      end
      self[:padding].read(padding)
    end

    def generate_tfc(opt)
      tfc = ''
      return tfc unless opt[:tfc]

      tfc_size = opt[:tfc_size] - self[:body].sz
      if tfc_size.positive?
        tfc_size = case confidentiality_mode
                   when 'cbc'
                     (tfc_size / 16) * 16
                   else
                     (tfc_size / 4) * 4
                   end
        tfc = "\0".b * tfc_size
      end
      tfc
    end

    def encrypt_body(opt, iv) # rubocop:disable Naming/MethodParameterName
      msg = self[:body].to_s + generate_tfc(opt)
      msg += self[:padding].to_s + self[:pad_length].to_s + self[:next].to_s
      enc_msg = encipher(msg)
      # as padding is used to pad for CBC mode, this is unused
      @conf.final

      encrypt_set_encrypted_fields(enc_msg, iv)
    end

    def encrypt_set_encrypted_fields(msg, iv) # rubocop:disable Naming/MethodParameterName
      self[:body] = BinStruct::String.new.read(iv)
      self[:body] << msg[0..-3]
      self[:pad_length].read msg[-2]
      self[:next].read msg[-1]

      # reset padding field as it has no sense in encrypted ESP
      self[:padding].read ''
    end

    def set_esp_icv_if_needed
      return unless authenticated?

      if @conf.authenticated?
        self[:icv].read @conf.auth_tag[0, @icv_length]
      else
        self[:icv].read @intg.digest[0, @icv_length]
      end
    end

    def remove_enciphered_packets
      id = header_id(self)
      return if id >= packet.headers.size - 1

      (packet.headers.size - 1).downto(id + 1) do |index|
        packet.headers.delete_at index
      end
    end

    def check_icv_length(opt)
      raise PacketGen::ParseError, 'unknown ICV size' unless opt[:icv_length]

      @icv_length = opt[:icv_length].to_i
    end

    def decrypt_format_packet
      # reread ESP to handle new ICV size
      msg = self[:body].to_s + self[:pad_length].to_s
      msg << self[:next].to_s
      read_icv_dependent_fields(msg)
      read_icv(msg)
    end

    def private_decrypt(options)
      plain_msg = decrypt_body
      # check authentication tag
      return false if authenticated? && !authenticate!

      new_pkt = fill_decrypted_fields_and_generate_plain_packet(plain_msg)
      packet.encapsulate new_pkt if options[:parse] && !new_pkt.nil?
      true
    end

    def decrypt_body
      msg = self.body.to_s
      msg += self.padding + self[:pad_length].to_s + self[:next].to_s
      decipher(msg)
    end

    def fill_decrypted_fields_and_generate_plain_packet(plain_msg)
      self[:body].read plain_msg[0..-3]
      self[:pad_length].read plain_msg[-2]
      self[:next].read plain_msg[-1]

      fill_padding_field
      generate_plain_pkt
    end

    def fill_padding_field
      return unless self.pad_length.positive?

      len = self.pad_length
      self[:padding].read self[:body].slice!(-len, len)
    end

    def generate_plain_pkt # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      case self.next
      when 4   # IPv4
        pkt = PacketGen::Packet.parse(body, first_header: 'IP')
        encap_length = pkt.ip.length
      when 41  # IPv6
        pkt = PacketGen::Packet.parse(body, first_header: 'IPv6')
        encap_length = pkt.ipv6.length + pkt.ipv6.sz
      when PacketGen::Header::ICMP::IP_PROTOCOL
        pkt = PacketGen::Packet.parse(body, first_header: 'ICMP')
        # no size field. cannot recover TFC padding
        encap_length = self[:body].sz
      when PacketGen::Header::UDP::IP_PROTOCOL
        pkt = PacketGen::Packet.parse(body, first_header: 'UDP')
        encap_length = pkt.udp.length
      when PacketGen::Header::TCP::IP_PROTOCOL
        # No length in TCP header, so TFC may not be used.
        # Or underlayer protocol should have a size information...
        pkt = PacketGen::Packet.parse(body, first_header: 'TCP')
        encap_length = pkt.sz
      when PacketGen::Header::ICMPv6::IP_PROTOCOL
        pkt = PacketGen::Packet.parse(body, first_header: 'ICMPv6')
        # no size field. cannot recover TFC padding
        encap_length = self[:body].sz
      else
        # Unmanaged encapsulated protocol
        pkt = nil
        encap_length = self[:body].sz
      end

      remove_tfc_if_needed(encap_length)
      pkt
    end

    def remove_tfc_if_needed(real_length)
      return if real_length == self[:body].sz

      tfc_len = self[:body].sz - real_length
      self[:tfc].read self[:body].slice!(real_length, tfc_len)
    end
  end

  PacketGen::Header.add_class ESP

  PacketGen::Header::IP.bind ESP, protocol: ESP::IP_PROTOCOL
  PacketGen::Header::IPv6.bind ESP, next: ESP::IP_PROTOCOL
  PacketGen::Header::UDP.bind ESP, procs: [->(f) { f.dport = f.sport = ESP::UDP_PORT },
                                           lambda { |f|
                                             (f.dport == ESP::UDP_PORT ||
                                             f.sport == ESP::UDP_PORT) &&
                                               BinStruct::Int32.new.read(f.body[0..3]).to_i.positive?
                                           }]
  ESP.bind PacketGen::Header::IP, next: 4
  ESP.bind PacketGen::Header::IPv6, next: 41
  ESP.bind PacketGen::Header::TCP, next: PacketGen::Header::TCP::IP_PROTOCOL
  ESP.bind PacketGen::Header::UDP, next: PacketGen::Header::TCP::IP_PROTOCOL
  ESP.bind PacketGen::Header::ICMP, next: PacketGen::Header::ICMP::IP_PROTOCOL
  ESP.bind PacketGen::Header::ICMPv6, next: PacketGen::Header::ICMPv6::IP_PROTOCOL
end
# rubocop:enable Metrics/ClassLength
