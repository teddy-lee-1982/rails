module ActionController
  class AuthenticityToken
    LENGTH = 32

    # Note that this will modify +session+ as a side-effect if there is
    # not a master CSRF token already present
    def initialize(session, logger = nil)
      session[:_csrf_token] ||= SecureRandom.base64(LENGTH)
      @master_csrf_token = Base64.strict_decode64(session[:_csrf_token])
      @logger = logger
    end

    def generate_masked
      # Start with some random bits
      one_time_pad = SecureRandom.random_bytes(LENGTH)

      # XOR the random bits with the real token and concatenate them
      masked_token = self.class.xor_byte_strings(one_time_pad, @master_csrf_token)

      Base64.strict_encode64(one_time_pad.concat(masked_token))
    end

    def secure_compare(a, b)
      ActiveSupport::MessageVerifier.new('').send(:secure_compare, a, b)
    end

    def valid?(encoded_payload)
      return false unless encoded_payload

      decoded_payload = Base64.strict_decode64(encoded_payload)

      # See if it's actually a masked token or not. In order to
      # deploy this code, we should be able to handle any unmasked
      # tokens that we've issued without error.
      if decoded_payload.length == LENGTH
        # This is actually an unmasked token
        if @logger
          @logger.warn "The client is using an unmasked CSRF token. This " +
            "should only happen immediately after you upgrade to masked " +
            "tokens; if this persists, something is wrong."
        end

        secure_compare(decoded_payload, @master_csrf_token)

      elsif decoded_payload.length == LENGTH * 2
        # Split the token into the one-time pad and the encrypted
        # value and decrypt it
        one_time_pad = decoded_payload.first(LENGTH)
        masked_token = decoded_payload.last(LENGTH)
        csrf_token = self.class.xor_byte_strings(one_time_pad, masked_token)

        secure_compare(csrf_token, @master_csrf_token)

      else
        # Malformed token of some strange length
        false

      end
    end

    def self.xor_byte_strings(s1, s2)
      s1.bytes.zip(s2.bytes).map! { |c1, c2| c1 ^ c2 }.pack('c*')
    end
  end
end
