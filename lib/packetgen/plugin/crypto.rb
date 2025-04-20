# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  # Mixin for cryptographic classes
  # @api private
  # @author Sylvain Daubert
  module Crypto
    # Cryptographic error
    class Error < PacketGen::Error; end

    # Register cryptographic modes
    # @param [OpenSSL::Cipher] conf
    # @param [OpenSSL::HMAC] intg
    # @return [void]
    def set_crypto(conf, intg)
      @conf = conf
      @intg = intg
      return unless conf.authenticated?

      # #auth_tag_len only supported from ruby 2.4.0
      @conf.auth_tag_len = @trunc if @conf.respond_to? :auth_tag_len
    end

    # Get confidentiality mode name
    # @return [String]
    def confidentiality_mode
      mode = @conf.name.match(/-([^-]*)$/)[1]
      raise Error, 'unknown cipher mode' if mode.nil?

      mode.downcase
    end

    # Say if crypto modes permit authentication
    # @return [Boolean]
    def authenticated?
      @conf.authenticated? || !@intg.nil?
    end

    # Check authentication
    # @return [Boolean]
    def authenticate!
      @conf.final
      if @intg
        @intg.update @esn.to_s if defined? @esn
        @intg.digest[0, @icv_length] == @icv
      else
        true
      end
    rescue OpenSSL::Cipher::CipherError
      false
    end

    # Encipher +data+
    # @param [String] data
    # @return [String] enciphered data
    def encipher(data)
      enciphered_data = @conf.update(data)
      @intg&.update(enciphered_data)
      enciphered_data
    end

    # Decipher +data+
    # @param [String] data
    # @return [String] deciphered data
    def decipher(data)
      @intg&.update(data)
      @conf.update(data)
    end

    # Compute and set IV for deciphering mode
    # @param [BinStruct::String] salt
    # @param [String] msg ciphered message
    # @return [String] iv
    def compute_iv_for_decrypting(salt, msg)
      case confidentiality_mode
      when 'gcm'
        iv = msg.slice!(0, 8)
        real_iv = salt + iv
      when 'cbc'
        @conf.padding = 0
        real_iv = iv = msg.slice!(0, 16)
      when 'ctr'
        iv = msg.slice!(0, 8)
        real_iv = salt + iv + [1].pack('N')
      else
        real_iv = iv = msg.slice!(0, 16)
      end
      @conf.iv = real_iv
      iv
    end

    # Compute and set real IV for ciphering mode
    # @param [String] iv IV to use
    # @param [String] salt salt to use
    # @return [void]
    def compute_iv_for_encrypting(iv, salt) # rubocop:disable Naming/MethodParameterName
      real_iv = force_binary(salt) + force_binary(iv)
      real_iv += [1].pack('N') if confidentiality_mode == 'ctr'
      @conf.iv = real_iv
    end
  end
end
