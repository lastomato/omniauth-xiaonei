require "faraday"
require "digest/md5"
require "omniauth/strategies/oauth2"

module OmniAuth
  module Strategies
    class Renren < OmniAuth::Strategies::OAuth2
      option :name, "renren"

      option :client_options, {
        :site => "https://graph.renren.com"
      }

      option :token_params, {
        :grant_type => "authorization_code"
      }

      #option :api_url, "http://api.renren.com/restserver.do"

      def request_phase
        redirect client.auth_code.authorize_url({:redirect_uri => callback_url}.merge(authorize_params))
      end

      def raw_info
        opts = {
          :method => "users.getInfo",
          :v      => "1.0",
          :format => "JSON",
          :access_token => access_token.token
        }.merge!(fields)
        conn = Faraday.new(:url => "http://api.renren.com") do |faraday|
          faraday.request  :url_encoded
          faraday.response :logger
          faraday.adapter  Faraday.default_adapter
        end
        @raw_info ||= parse(conn.post("/restserver.do", append_sig(opts)).body).first || {}
      end

      uid {
        raw_info[:uid.to_s]
      }

      info {
        (options[:fields] || "name,email_hash,tinyurl,headurl,zidou,star").split(",").inject({}) { |t,v| t[v.to_sym] = raw_info[v];t }
      }

      extra {
        hash = {}
        hash["raw_info"] = raw_info unless skip_info?
        prune! hash
      }

      private
        def append_sig(opts = {})
          opts.merge!({ :sig => Digest::MD5.hexdigest(opts.inject([]) { |t, v| t << v.join("=") }.sort.join + options.client_secret) })
        end

        def fields
          options[:fields] ? { :fields => options[:fields] } : {}
        end

        def prune!(hash)
          hash.delete_if do |_, value|
            prune!(value) if value.is_a?(Hash)
            value.nil? || (value.respond_to?(:empty?) && value.empty?)
          end
        end

        def parse(content)
          lambda { |body| MultiJson.respond_to?(:adapter) ? MultiJson.load(body) : MultiJson.decode(body) rescue body }.call(content)
        end
    end
  end
end