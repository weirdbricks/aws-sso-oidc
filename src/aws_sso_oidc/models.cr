module AwsSsoOidc
  struct Registration
    getter client_id : String
    getter client_secret : String
    getter client_id_issued_at : Int64
    getter client_secret_expires_at : Int64

    def initialize(@client_id, @client_secret, @client_id_issued_at, @client_secret_expires_at)
    end
  end

  struct DeviceAuthorization
    getter device_code : String
    getter user_code : String
    getter verification_uri : String
    getter verification_uri_complete : String
    getter expires_in : Int32
    getter interval : Int32

    def initialize(@device_code, @user_code, @verification_uri, @verification_uri_complete, @expires_in, @interval)
    end
  end

  struct TokenResult
    getter access_token : String
    getter expires_in : Int32
    getter refresh_token : String?

    def initialize(@access_token, @expires_in, @refresh_token)
    end
  end
end
