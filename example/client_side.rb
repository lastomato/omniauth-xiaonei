# -*- encoding: utf-8 -*-

require "sinatra"
require "omniauth-xiaonei"
require "multi_json"

use Rack::Session::Cookie

# set your api_key and api_secret here
use OmniAuth::Builder do
  provider :xiaonei, API_KEY, API_SECRET
end

# sending request
get "/" do 
  redirect "/auth/xiaonei"
end

# callback phase
get "/auth/:provider/callback" do
  content_type "application/json"
  begin
    MultiJson.encode(request.env)
  rescue Exception => e
  end
end

# in case of failure
get "/auth/failure" do
  content_type "application/json"
  MultiJson.encode(request.env)
end
