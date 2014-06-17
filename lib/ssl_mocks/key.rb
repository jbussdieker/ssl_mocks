module SSLMocks
  class Key
    attr_accessor :wrapped_object

    def initialize(param = 2048)
      if param.kind_of? Integer
        @wrapped_object = OpenSSL::PKey::RSA.new(param)
      elsif param.kind_of? String
        @wrapped_object = OpenSSL::PKey::RSA.new(param)
      elsif param.kind_of? IO
        @wrapped_object = OpenSSL::PKey::RSA.new(param.read)
      end
    end

    def to_s
      @wrapped_object.to_s
    end

    def method_missing(method_name, *args, &block)
      @wrapped_object.send(method_name, *args, &block)
    end
  end
end
