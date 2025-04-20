# coding: utf-8
# frozen_string_literal: true

# This file is part of IPsec packetgen plugin.
# See https://github.com/sdaubert/packetgen-plugin-ipsec for more informations
# Copyright (c) 2018 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen::Plugin
  class IKE
    # Transform attribute.
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |A|       Attribute Type        |    AF=0  Attribute Length     |
    #   |F|                             |    AF=1  Attribute Value      |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                   AF=0  Attribute Value                       |
    #   |                   AF=1  Not Transmitted                       |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # Such an attribute may have a TLV (Type/length/value) format if AF=0,
    # or a TV format (AF=1).
    # @author Sylvain Daubert
    class Attribute < BinStruct::Struct
      # KeyLength attribute type
      TYPE_KEY_LENGTH = 14

      # @!attribute type
      #  attribute type
      #  @return [Integer]
      define_attr :type, BinStruct::Int16
      # @!attribute length
      #  attribute length
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute value
      #  attribute value
      #  @return [Integer]
      define_attr :value, BinStruct::Int32, optional: ->(h) { !h.tv_format? }

      def initialize(options={})
        super
        if tv_format?
          self[:length].value = (options[:value] & 0xffff)
        else
          self[:length].value = 8 unless options[:length]
        end
      end

      undef length, value

      # @return [Integer]
      def length
        tv_format? ? 4 : self[:length].to_i
      end

      # @return [Integer]
      def value
        tv_format? ? self[:length].to_i : self[:value].to_i
      end

      # Get a human readable string
      # @return [String]
      def to_human
        name = self.class.constants.grep(/TYPE_/)
                   .detect { |c| self.class.const_get(c) == (type & 0x7fff) } || "attr[#{type & 0x7fff}]"
        name = name.to_s.sub(/TYPE_/, '')
        "#{name}=#{value}"
      end

      # Say if attribute use TV format (+true+) or TLV one (+false+)
      # @return [Boolean]
      def tv_format?
        type & 0x8000 == 0x8000
      end
    end

    # Set of {Attribute} in a {Transform}
    # @author Sylvain Daubert
    class Attributes < BinStruct::Array
      set_of Attribute
    end

    # SA Tranform substructure, as defined in RFC 7296 §3.3.2
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Last Substruc |   RESERVED    |        Transform Length       |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |Transform Type |   RESERVED    |          Transform ID         |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                      Transform Attributes                     ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # == Create a Transform
    #  # using type and id names
    #  trans = PacketGen::Plugin::IKE::Transform.new(type: 'ENCR', id: 'AES_CBC')
    #  # using integer values
    #  trans = PacketGen::Plugin::IKE::Transform.new(type: 1, id: 12)
    # == Add attributes to a transform
    #  # using an Attribute object
    #  attr = PacketGen::Plugin::IKE::Attribute.new(type: 14, value: 128)
    #  trans.tattributes << attr
    #  # using a hash
    #  trans.tattributes << { type: 14, value: 128 }
    # @author Sylvain Daubert
    class Transform < BinStruct::Struct
      # Transform types
      TYPES = {
        'ENCR' => 1,
        'PRF' => 2,
        'INTG' => 3,
        'DH' => 4,
        'ESN' => 5
      }.freeze

      # DES encryption with 64-bit IV
      ENCR_DES_IV64          = 1
      # DES encryption
      ENCR_DES               = 2
      # 3DES encryption
      ENCR_3DES              = 3
      # RC5 integrity
      ENCR_RC5               = 4
      # IDEA encryption
      ENCR_IDEA              = 5
      # Cast encryption
      ENCR_CAST              = 6
      # Blowfish encryption
      ENCR_BLOWFISH          = 7
      # 3IDEA encryption
      ENCR_3IDEA             = 8
      # DES encryption with 32-bit IV
      ENCR_DES_IV32          = 9
      # AES with CBC mode encryption
      ENCR_AES_CBC           = 12
      # AES with CTR mode encryption
      ENCR_AES_CTR           = 13
      # AES with CCM mode encryption/authentication, 8-bytes ICV
      ENCR_AES_CCM8          = 14
      # AES with CCM mode encryption/authentication, 12-bytes ICV
      ENCR_AES_CCM12         = 15
      # AES with CCM mode encryption/authentication, 16-bytes ICV
      ENCR_AES_CCM16         = 16
      # AES with GCM mode encryption/authentication, 8-bytes ICV
      ENCR_AES_GCM8          = 18
      # AES with GCM mode encryption/authentication, 12-bytes ICV
      ENCR_AES_GCM12         = 19
      # AES with GCM mode encryption/authentication, 16-bytes ICV
      ENCR_AES_GCM16         = 20
      # CAMELLIA with CBC mode encryption
      ENCR_CAMELLIA_CBC      = 23
      # CAMELLIA with CTR mode encryption
      ENCR_CAMELLIA_CTR      = 24
      # CAMELLIA with CCM mode encryption/authentication, 8-bytes ICV
      ENCR_CAMELLIA_CCM8     = 25
      # CAMELLIA with CCM mode encryption/authentication, 12-bytes ICV
      ENCR_CAMELLIA_CCM12    = 26
      # CAMELLIA with CCM mode encryption/authentication, 16-bytes ICV
      ENCR_CAMELLIA_CCM16    = 27
      # CHACHA20 encryption with POLY1035 authentication
      ENCR_CHACHA20_POLY1305 = 28

      # PRF with HMAC on MD5
      PRF_HMAC_MD5      = 1
      # PRF with HMAC on SHA-1
      PRF_HMAC_SHA1     = 2
      # PRF with AES-128 with XCBC mode
      PRF_AES128_XCBC   = 4
      # PRF with HMAC on SHA-256
      PRF_HMAC_SHA2_256 = 5
      # PRF with HMAC on SHA-384
      PRF_HMAC_SHA2_384 = 6
      # PRF with HMAC on SHA-512
      PRF_HMAC_SHA2_512 = 7
      # PRF with AES-128 withg CMAC mode
      PRF_AES128_CMAC   = 8

      # No integrity
      INTG_NONE              = 0
      # Integrity with HMAC on MD5, 96-bit ICV
      INTG_HMAC_MD5_96       = 1
      # Integrity with HMAC on SHA-1, 96-bit ICV
      INTG_HMAC_SHA1_96      = 2
      # Integrity with AES with XCBC mode, 96-bit ICV
      INTG_AES_XCBC_96       = 5
      # Integrity with HMAC on MD5, 128-bit ICV
      INTG_HMAC_MD5_128      = 6
      # Integrity with HMAC on SHA-1, 128-bit ICV
      INTG_HMAC_SHA1_160     = 7
      # Integrity with AES with CMAC mode, 96-bit ICV
      INTG_AES_CMAC_96       = 8
      # Integrity with AES-128 with GMAC mode, 128-bit ICV
      INTG_AES128_GMAC      = 9
      # Integrity with AES-192 with GMAC mode, 128-bit ICV
      INTG_AES192_GMAC      = 10
      # Integrity with AES-256 with GMAC mode, 128-bit ICV
      INTG_AES256_GMAC      = 11
      # Integrity with HMAC on SHA-256, 128-bit ICV
      INTG_HMAC_SHA2_256_128 = 12
      # Integrity with HMAC on SHA-384, 192-bit ICV
      INTG_HMAC_SHA2_384_192 = 13
      # Integrity with HMAC on SHA-512, 256-bit ICV
      INTG_HMAC_SHA2_512_256 = 14

      # No key-exchange
      DH_NONE          = 0
      # Key exchange with Diffie-Hellman on modp-768 group
      DH_MODP768       = 1
      # Key exchange with Diffie-Hellman on modp-1024 group
      DH_MODP1024      = 2
      # Key exchange with Diffie-Hellman on modp-1536 group
      DH_MODP1536      = 5
      # Key exchange with Diffie-Hellman on modp-2048 group
      DH_MODP2048      = 14
      # Key exchange with Diffie-Hellman on modp-3072 group
      DH_MODP3072      = 15
      # Key exchange with Diffie-Hellman on modp-4096 group
      DH_MODP4096      = 16
      # Key exchange with Diffie-Hellman on modp-6144 group
      DH_MODP6144      = 17
      # Key exchange with Diffie-Hellman on modp-8192 group
      DH_MODP8192      = 18
      # Key exchange with Diffie-Hellman on NIST p256 Elliptic curve
      DH_ECP256        = 19
      # Key exchange with Diffie-Hellman on NIST p384 Elliptic curve
      DH_ECP384        = 20
      # Key exchange with Diffie-Hellman on NIST p521 Elliptic curve
      DH_ECP521        = 21
      # Key exchange with Diffie-Hellman on Brainpool P224 Elliptic curve
      DH_BRAINPOOLP224 = 27
      # Key exchange with Diffie-Hellman on Brainpool P256 Elliptic curve
      DH_BRAINPOOLP256 = 28
      # Key exchange with Diffie-Hellman on Brainpool P384 Elliptic curve
      DH_BRAINPOOLP384 = 29
      # Key exchange with Diffie-Hellman on Brainpool P512 Elliptic curve
      DH_BRAINPOOLP512 = 30
      # Key exchange with Diffie-Hellman on curve25519 Elliptic curve
      DH_CURVE25519    = 31
      # Key exchange with Diffie-Hellman on curve448 Elliptic curve
      DH_CURVE448      = 32

      # No Extended Sequence Number
      ESN_NO_ESN = 0
      # Use Extended Sequence Number
      ESN_ESN    = 1

      # @!attribute last
      #  8-bit last substructure. Specifies whether or not this is the
      #  last Transform Substructure in the Proposal. This field has a value of 0
      #  if this was the last Transform Substructure, and a value of 3 if
      #  there are more Transform Substructures.
      #  @return [Integer]
      define_attr :last, BinStruct::Int8
      # @!attribute rsv1
      #  8-bit reserved field
      #  @return [Integer]
      define_attr :rsv1, BinStruct::Int8
      # @!attribute length
      #  16-bit transform length
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute [r] type
      #  8-bit transform type. The Transform Type is the cryptographic
      #  algorithm type (i.e. encryption, PRF, integrity, etc.)
      #  @return [Integer]
      define_attr :type, BinStruct::Int8Enum, enum: TYPES
      # @!attribute rsv2
      #  8-bit reserved field
      #  @return [Integer]
      define_attr :rsv2, BinStruct::Int8
      # @!attribute [r] id
      #  16-bit transform ID. The Transform ID is the specific instance of
      #  the proposed transform type.
      #  @return [Integer]
      define_attr :id, BinStruct::Int16
      # @!attribute tattributes
      #  Set of attributes for this transform
      #  @return [Attributes]
      define_attr :tattributes, Attributes, builder: ->(h, t) { t.new(length_from: -> { h.length - h.offset_of(:tattributes) }) }

      def initialize(options={})
        super
        self.type = options[:type] if options[:type]
        self.id = options[:id] if options[:id]
        self[:length].value = sz unless options[:length]
      end

      undef id=

      # Set transform ID
      # @param [Integer,String] value
      # @return [Integer]
      def id=(value)
        id = case value
             when Integer
               value
             else
               c = self.class.constants.grep(/#{human_type}_#{value}/).first
               c ? self.class.const_get(c) : nil
             end
        raise ArgumentError, "unknown ID #{value.inspect}" unless id

        self[:id].value = id
      end

      # Compute length and set {#length} field
      # @return [Integer] new length
      def calc_length
        PacketGen::Header::Base.calculate_and_set_length self
      end

      # Get a human readable string
      # @return [String]
      def to_human
        h = +"#{human_type}(#{human_id}"
        h << ",#{tattributes.to_human}" unless tattributes.empty?

        h << ')'
      end

      # Get human-readable type
      # @return [String]
      def human_type
        if self[:type].enum.value? self.type
          self[:type].to_human
        else
          "type[#{self.type}]"
        end
      end

      # Get human-readable ID
      # @return [String]
      def human_id
        name = self.class.constants.grep(/#{human_type}_/)
                   .detect { |c| self.class.const_get(c) == id } || "ID=#{id}"
        name.to_s.sub(/#{human_type}_/, '')
      end

      # Say if this transform is the last one (from {#last} field)
      # @return [Boolean,nil] returns a Boolean when {#last} has defined value (+0+ => +true+, +3+ => +false+), else +nil+ is returned.
      def last?
        case last
        when 0
          true
        when 3
          false
        end
      end
    end

    # Set of {Transform} in a {SAProposal}
    # @author Sylvain Daubert
    class Transforms < BinStruct::Array
      set_of Transform

      # Same as {BinStruct::Array#push} but update previous {Transform#last} attribute
      # @see BinStruct::Array#push
      def push(trans)
        super
        self[-2].last = 3 if size > 1
        self[-1].last = 0
        self
      end
    end

    # SA Proposal, as defined in RFC 7296 §3.3.1
    #                          1                   2                   3
    #      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     | Last Substruc |   RESERVED    |         Proposal Length       |
    #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
    #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     ~                        SPI (variable)                         ~
    #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     |                                                               |
    #     ~                        <Transforms>                           ~
    #     |                                                               |
    #     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # == Create a proposal
    #  # using protocol name
    #  proposal = PacketGen::Plugin::IKE::Proposal.new(num: 1, protocol: 'IKE')
    #  # using integer values
    #  proposal = PacketGen::Plugin::IKE::Proposal.new(num: 1, protocol: 1)
    # == Add transforms to a proposal
    #  # using a Transform object
    #  trans = PacketGen::Plugin::IKE::Transform.new(type: 'ENCR', id: '3DES')
    #  proposal.transforms << trans
    #  # using a hash
    #  proposal.transforms << { type: 'ENCR', id: '3DES' }
    # @author Sylvain Daubert
    class SAProposal < BinStruct::Struct
      # @!attribute last
      #  8-bit last substructure. Specifies whether or not this is the
      #  last Proposal Substructure in the SA. This field has a value of 0
      #  if this was the last Proposal Substructure, and a value of 2 if
      #  there are more Proposal Substructures.
      #  @return [Integer]
      define_attr :last, BinStruct::Int8
      # @!attribute reserved
      #  8-bit reserved field
      #  @return [Integer]
      define_attr :reserved, BinStruct::Int8
      # @!attribute length
      #  16-bit proposal length
      #  @return [Integer]
      define_attr :length, BinStruct::Int16
      # @!attribute num
      #  8-bit proposal number. When a proposal is made, the first
      #  proposal in an SA payload MUST be 1, and subsequent proposals MUST
      #  be one more than the previous proposal (indicating an OR of the
      #  two proposals).  When a proposal is accepted, the proposal number
      #  in the SA payload MUST match the number on the proposal sent that
      #  was accepted.
      #  @return [Integer]
      define_attr :num, BinStruct::Int8, default: 1
      # @!attribute [r] protocol
      #  8-bit protocol ID. Specify IPsec protocol currently negociated.
      #  May 1 (IKE), 2 (AH) or 3 (ESP).
      #  @return [Integer]
      define_attr :protocol, BinStruct::Int8Enum, enum: PROTOCOLS
      # @!attribute spi_size
      #  8-bit SPI size. Give size of SPI field. Set to 0 for an initial IKE SA
      #  negotiation, as SPI is obtained from outer Plugin.
      #  @return [Integer]
      define_attr :spi_size, BinStruct::Int8, default: 0
      # @!attribute num_trans
      #  8-bit number of transformations
      #  @return [Integer]
      define_attr :num_trans, BinStruct::Int8, default: 0
      # @!attribute spi
      #   the sending entity's SPI. When the {#spi_size} field is zero,
      #   this field is not present in the proposal.
      #   @return [String]
      define_attr :spi, BinStruct::String, builder: ->(h, t) { t.new(length_from: h[:spi_size]) }
      # @!attribute transforms
      #  8-bit set of tranforms for this proposal
      #  @return [Transforms]
      define_attr :transforms, Transforms, builder: ->(h, t) { t.new(counter: h[:num_trans]) }

      def initialize(options={})
        options[:spi_size] = options[:spi].size if options[:spi] && options[:spi_size].nil?
        super
        self.length = sz unless options[:length]
        self.protocol = options[:protocol] if options[:protocol]
      end

      # Compute length and set {#length} field
      # @return [Integer] new length
      def calc_length
        transforms.each(&:calc_length)
        PacketGen::Header::Base.calculate_and_set_length self
      end

      # Get a human readable string
      # @return [String]
      def to_human
        str = +"##{num} #{human_protocol}"
        case spi_size
        when 4
          str << ('(spi:0x%08x)' % BinStruct::Int32.new.read(spi).to_i)
        when 8
          str << ('(spi:0x%016x)' % BinStruct::Int64.new.read(spi).to_i)
        end
        str << ":#{transforms.to_human}"
      end

      # Get protocol name
      # @return [String]
      def human_protocol
        self[:protocol].to_human
      end

      # Say if this proposal is the last one (from {#last} field)
      # @return [Boolean,nil] returns a Boolean when {#last} has defined value
      #    (+0+ => +true+, +2+ => +false+), else +nil+ is returned.
      def last?
        case last
        when 0
          true
        when 2
          false
        end
      end
    end

    # Set of {SAProposal}
    # @author Sylvain Daubert
    class SAProposals < BinStruct::Array
      set_of SAProposal

      # Separator used between proposals in {#to_human}
      HUMAN_SEPARATOR = '; '

      # Same as {BinStruct::Array#push} but update previous {SAProposal#last} attribute
      # @see BinStruct::Array#push
      def push(prop)
        super
        self[-2].last = 2 if size > 1
        self[-1].last = 0
        self
      end
    end

    # This class handles Security Assocation payloads, as defined in RFC 7296 §3.3.
    #
    # A SA payload contains a generic payload Plugin (see {Payload}) and a set of
    # {SAProposal} ({#proposals} field, which is a {SAProposals} object):
    #                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   | Next Payload  |C|  RESERVED   |         Payload Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   ~                          <Proposals>                          ~
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # == Create a SA payload
    #   # Create a IKE packet with a SA payload
    #   pkt = PacketGen.gen('IP').add('UDP').add('IKE').add('IKE::SA')
    #   # add a proposal. Protocol name is taken from SAProposal::PROTO_* constants
    #   pkt.ike_sa.proposals << { num: 1, protocol: 'ESP' }
    #   # add a transform to this proposal.
    #   # type name is taken from Transform::TYPE_* constants.
    #   # ID is taken from Transform::<TYPE>_* constants.
    #   pkt.ike_sa.proposals.first.transforms << { type: 'ENCR', id: 'AES_CTR' }
    #   # and finally, add an attribute to this transform (here, KEY_SIZE = 128 bits)
    #   pkt.ike_sa.proposals[0].transforms[0].tattributes << { type: 0x800e, value: 128 }
    #   pkt.calc_length
    # @author Sylvain Daubert
    class SA < Payload
      # Payload type number
      PAYLOAD_TYPE = 33

      remove_attr :content

      # @!attribute proposals
      #  Set of SA proposals
      #  @return [SAProposals]
      define_attr_before :body, :proposals, SAProposals, builder: ->(h, t) { t.new(length_from: -> { h.length - h.offset_of(:proposals) }) }

      # Compute length and set {#length} field
      # @return [Integer] new length
      def calc_length
        proposals.each(&:calc_length)
        super
      end
    end
  end

  PacketGen::Header.add_class IKE::SA
end
