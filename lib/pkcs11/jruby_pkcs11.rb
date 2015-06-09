require 'java'
java_import 'sun.security.pkcs11.wrapper.PKCS11Constants'
java_import 'sun.security.pkcs11.wrapper.CK_ATTRIBUTE'

module PKCS11
  # NOTE: Hack to re-open PKCS11 module and create constants from Java library,
  # rather than the way they were being defined via the C Library.
  # TODO: should be able to iterate over everything in the PKCS11Constants
  # namespace and add them here via the wonders of metaprogramming.

  CKF_SERIAL_SESSION = PKCS11Constants::CKF_SERIAL_SESSION

  CKK_RSA = PKCS11Constants::CKK_RSA

  CKO_CERTIFICATE = PKCS11Constants::CKO_CERTIFICATE
  CKO_DATA = PKCS11Constants::CKO_DATA
  CKO_PUBLIC_KEY = PKCS11Constants::CKO_PUBLIC_KEY
end

class JRubyPkcs11
  class Session
    def initialize(p11, session_handle)
      @p11 = p11
      @session_handle = session_handle
    end

    def ck_type(type)
      # TODO: metaprogram the simple DSL
      case type
        when :CLASS
          PKCS11Constants::CKA_CLASS
        when :TOKEN
          PKCS11Constants::CKA_TOKEN
        when :APPLICATION
          PKCS11Constants::CKA_APPLICATION
        when :ID
          PKCS11Constants::CKA_ID
        when :KEY_TYPE
          PKCS11Constants::CKA_KEY_TYPE
        when :VALUE
          PKCS11Constants::CKA_VALUE
        else
          raise "UNRECOGNIZED CK ATTRIBUTE TYPE: #{type}"
      end
    end

    def to_ck_attribute(attribute)
      puts "CONVERTING ATTRIBUTE: #{attribute}"
      type, value = *attribute
      puts "TYPE/VALUE: #{ck_type(type)} / #{value}"
      CK_ATTRIBUTE.new(ck_type(type), value)
    end

    def to_ck_attributes(attributes)
      attributes.map {|a| to_ck_attribute(a) }
    end

    def create_object(attributes)
      @p11.C_CreateObject(@session_handle, to_ck_attributes(attributes))
    end

    def find_objects(attributes)
      @p11.C_FindObjectsInit(@session_handle, to_ck_attributes(attributes))
      # TODO: probably need to iterate over calls to this until there are no
      # more results?
      results = @p11.C_FindObjects(@session_handle, 100).to_a
      puts "FIND OBJECTS, RESULTS: #{results}"
      @p11.C_FindObjectsFinal(@session_handle)
      results
    end

    def info
      session_info = @p11.C_GetSessionInfo(@session_handle)
      {:flags => session_info.flags}
    end
  end

  class Slot
    def initialize(p11, slot_index)
      @p11 = p11
      @slot_index = slot_index
    end

    def C_OpenSession(flags)
      Session.new(@p11, @p11.C_OpenSession(@slot_index, flags, nil, nil))
    end
  end

  def initialize
    # TODO use the real so path
    so_path = "/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so"
    @p11 = Java::SunSecurityPkcs11Wrapper::PKCS11.getInstance(so_path, "C_GetFunctionList", nil, false)
  end

  def active_slots
    slots = @p11.C_GetSlotList(true)
    puts "SLOTS: (#{slots.class}) #{slots}"
    slots.map { |s| Slot.new(@p11, s) }
  end
end