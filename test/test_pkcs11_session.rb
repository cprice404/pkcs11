require "test/unit"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Session < Test::Unit::TestCase
  include PKCS11
  
  attr_reader :slots
  attr_reader :slot
  attr_reader :session
  
  TestCert_ID = "\230Z\275=\2614\236\337\fY\017Y\346\202\212\v\025\335\0239"

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
    
    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    @session = slot.C_OpenSession(flags)
    @session.login(:USER, "")
  end

  def teardown
    @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_find_objects
    obj = session.find_objects(:CLASS => CKO_CERTIFICATE)
    assert obj.length>2, 'There should be some certificates in the test database'
    assert_equal PKCS11::Object, obj.first.class, 'Retuned objects should be class Object'
    
    session.find_objects(:CLASS => CKO_CERTIFICATE) do |obj|
      assert obj[:SUBJECT], 'A certificate should have a subject'
      assert OpenSSL::X509::Name.new(obj[:SUBJECT]).to_s =~ /\/CN=/i, 'Every certificate should have a CN in the subject'
    end
  end

  def test_random
    session.seed_random('some entropy')
    rnd1 = session.generate_random(13)
    assert_equal rnd1.length, 13, 'expected length'
    rnd2 = session.generate_random(13)
    assert_equal rnd2.length, 13, 'expected length'
    assert_not_equal rnd1, rnd2, 'Two random blocks should be different'
  end

  def test_session_info
    info = session.info
    assert info.inspect =~ /flags=/, 'Session info should have a flag attribute'
  end
  
  def test_create_data_object
    obj = session.create_object(
      :CLASS=>CKO_DATA,
      :TOKEN=>false,
      :APPLICATION=>'My Application',
      :VALUE=>'value')
  end
  
  def test_create_certificate_object
    obj1 = session.find_objects(:CLASS => CKO_CERTIFICATE, :ID=>TestCert_ID).first

    obj = session.create_object(
      :CLASS=>CKO_CERTIFICATE,
      :SUBJECT=>obj1[:SUBJECT],
      :TOKEN=>false,
      :LABEL=>'test_create_object',
      :CERTIFICATE_TYPE=>CKC_X_509,
      :ISSUER=>obj1[:ISSUER],
      :VALUE=>obj1[:VALUE],
      :SERIAL_NUMBER=>'12345'
    )
    
    assert_equal '12345', obj[:SERIAL_NUMBER], 'Value as created'
  end
  
  def test_create_public_key_object
    rsa = OpenSSL::PKey::RSA.generate(512)
  
    obj = session.create_object(
      :CLASS=>CKO_PUBLIC_KEY,
      :KEY_TYPE=>CKK_RSA,
      :TOKEN=>false,
      :MODULUS=>rsa.n.to_s(2),
      :PUBLIC_EXPONENT=>rsa.e.to_s(2),
      :LABEL=>'test_create_public_key_object')
    
    assert_equal 'test_create_public_key_object', obj[:LABEL], 'Value as created'
  end
end
