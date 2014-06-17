module SSLMocks
  class Certificate
    def initialize(params)
      if params.kind_of? Hash
        @wrapped_object = OpenSSL::X509::Certificate.new.tap do |cert|
          OpenSSL::X509::Name.new.tap do |name|
            name.add_entry("CN", params[:common_name])
            cert.serial = 0
            cert.version = 0
            cert.subject = name
            cert.not_before = Time.now
            cert.not_after = Time.now + 3600
          end
        end
      elsif params.kind_of? String
        @wrapped_object = OpenSSL::X509::Certificate.new(params)
      elsif params.kind_of? IO
        @wrapped_object = OpenSSL::X509::Certificate.new(params.read)
      end
    end

    def to_s
      @wrapped_object.to_s
    end

    def sign(key, cert, algorithm = OpenSSL::Digest::SHA512.new)
      @wrapped_object.issuer = cert.subject
      @wrapped_object.sign(key.wrapped_object, algorithm)
    end

    def sign_ca(key, algorithm = OpenSSL::Digest::SHA512.new)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = @wrapped_object
      ef.issuer_certificate = @wrapped_object
      @wrapped_object.extensions = [
        ef.create_extension("basicConstraints","CA:TRUE", true),
        ef.create_extension("subjectKeyIdentifier", "hash"),
        # ef.create_extension("keyUsage", "cRLSign,keyCertSign", true),
      ]
      other = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
      @wrapped_object.add_extension(other)
      @wrapped_object.public_key = key.public_key
      @wrapped_object.issuer = @wrapped_object.subject
      sign(key, @wrapped_object, algorithm)
    end

    def method_missing(method_name, *args, &block)
      @wrapped_object.send(method_name, *args, &block)
    end
  end
end
