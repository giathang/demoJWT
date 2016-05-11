### WELCOME TO DEMO JWT


JWT is designed to validate the use of which may be exchanged in many different systems.

JWT mang thông tin dưới dạng JSON, có thể sử dụng ở hầu hết các ngôn ngữ lập trình phổ biến hiện nay nên nó có thể dễ dàng được sử dụng từ hệ thống này mang sang hệ thống khác mà không gặp vấn đề gì.

JWT là một chuỗi các ký tự đã được mã hoá nên có thể dễ dàng truyền theo dưới dạng param trên URL hoặc truyền trong header.

Cấu trúc của JWT

JWT được hép từ 3 phần và cách nhau bởi dấu chấm.

	xxxxx.yyyyyy.zzzzz

Phần thứ nhất là header, phần 2 là payload và phần thứ 3 là signature

1. Header: bao gồm 2 phần
	* kiểu token (ví dụ: JWT)
	* kiểu thuật toán băm ( VD: HS256 ) -> header

		{
			"typ": "JWT",
			"alg": "HS256"
		}

	và header sau khi mã hoá base64:
		aeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

2. Payload: phần này mang nhiều thông tin quan trọng cuả token, được chia làm 3 phần private, public, và registered.
	* registered: phần tên riêng của mỗi token, có thể có hoặc không
	* private: là phần thoả hiệp giữa 2 bên client và server cần xác thực, chú ý cẩn thận với phần này.
	* public : ta có thể tạo các thông tin xác thực thông qua phần này. ví dụ:

		{
			"iss": "sitepoint.com",
			"name": "Devdatta Kane",
			"admin": true
		}
	Và sau khi mã hoá base64:

	ew0KICAiaXNzIjogInNpdGVwb2ludC5jb20iLA0KICAibmFtZSI6ICJEZXZkYXR0YSBLYW5lIiwNCiAgImFkbWluIjogdHJ1ZQ0KfQ

3. Signature: Đây là phần quan trọng nhất, Nó được tạo ra bằng cách mã hoá HMACSHA256 từ 2 thành phần ở trên là header, payload và kết hợp với chuỗi secret lấy từ server
	require "openssl"
	require "base64"

	var encodedString = Base64.encode64(header) + "." + Base64.encode64(payload);
	hash  = OpenSSL::HMAC.digest("sha256", "secret", encodedString)

Vì secret key được lưu trên server nên sẽ hạn chế việc tác động từ bên ngoài đến payload và mỗi tác động nào thì đều bị server phát hiện thông qua signature.

Phần signatur sẽ có dạng mã hoá như sau:

	2b3df5c199c0b31d58c3dc4562a6e1ccb4a33cced726f3901ae44a04c8176f37 

Tổng hợp 3 phần header, payload và signature vào ta sẽ được JWT hoàn chỉnh để gửi kèm trong mỗi request

	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ew0KICAiaXNzIjogInNpdGVwb2ludC5jb20iLA0KICAibmFtZSI6ICJEZXZkYXR0YSBLYW5lIiwNCiAgImFkbWluIjogdHJ1ZQ0KfQ.2b3df5c199c0b31d58c3dc4562a6e1ccb4a33cced726f3901ae44a04c8176f37


### Demo
 	
 	1. Use 2 gem :

 		gem 'divise'
 		gem 'jwt'

 	2. In folder lib . create json_web_token.rb . In this class . create function to perform encode and decode

 		class JsonWebToken
		  def self.encode(payload)
		    JWT.encode(payload, Rails.application.secrets.secret_key_base)
		  end

		  def self.decode(token)
		    return HashWithIndifferentAccess.new(JWT.decode(token, Rails.application.secrets.secret_key_base)[0])
		  rescue
		    nil
		  end
		end

	3. Next  want use json_web_token . to cofig/initializers create jwt.rb call it

		require 'json_web_token'

	4. In applicaiton_helper all function request to use application

		class ApplicationController < ActionController::Base
		  attr_reader :current_user

		  protected
		  def authenticate_request!
		    unless user_id_in_token?
		      render json: { errors: ['Not Authenticated'] }, status: :unauthorized
		      return
		    end
		    @current_user = User.find(auth_token[:user_id])
		  rescue JWT::VerificationError, JWT::DecodeError
		    render json: { errors: ['Not Authenticated'] }, status: :unauthorized
		  end

		  private

		  def http_token
		      @http_token ||= if request.headers['Authorization'].present?
		        request.headers['Authorization'].split(' ').last
		      end
		  end

		  def auth_token
		    @auth_token ||= JsonWebToken.decode(http_token)
		  end

		  def user_id_in_token?
		    http_token && auth_token && auth_token[:user_id].to_i
		  end
		end

	5. Create AuthenticationController to check all  authenticate request  to API

		class AuthenticationController < ApplicationController
		  def authenticate_user
		    user = User.find_for_database_authentication(email: params[:email])
		    if user.valid_password?(params[:password])
		      render json: payload(user)
		    else
		      render json: {errors: ['Invalid Username/Password']}, status: :unauthorized
		    end
		  end

		  private

		  def payload(user)
		    return nil unless user and user.id
		    {
		      auth_token: JsonWebToken.encode({user_id: user.id}),
		      user: {id: user.id, email: user.email}
		    }
		  end
		end

	6. use authenticate_request! to check every request in application through before_action in home_controller

		class HomeController < ApplicationController
		  before_action :authenticate_request!
		​
		  def index
		    render json: {'logged_in' -> true}
		  end
		end

	7.  Test authenticate through postman and curl 

		Create User 
			>  User.create(email:'thang@gmail.com', password:'123456', password_confirmation:'123456')

		Test request Api through post man 

			return {"errors":["Not Authenticated"]}

		next test POST http://localhost3000/auth_user

			return {"auth_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.xRBfFjbkUjCT2hji-Uvv1yGzVfLsvXTuXi3cj2_t28w","user":{"id":2,"email":"1@1.com"}}

		next return home together with the header contains code JWT

			curl --header "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.xRBfFjbkUjCT2hji-Uvv1yGzVfLsvXTuXi3cj2_t28w" http://localhost:3000/home


		result

			{"logged_in":true}



### REFERENCE
	
	[ruby-jwt](https://github.com/jwt/ruby-jwt)
	[jwt](https://jwt.io/)

### Thanks









