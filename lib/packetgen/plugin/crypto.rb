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
  end
end
