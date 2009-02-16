require 'oauth/helper'
require 'oauth/client/helper'
require 'oauth/request_proxy/net_http'

module OAuth
  module Client
    module Net
      module HTTPRequest
        include OAuth::Helper

        attr_reader :oauth_helper

        # Add the OAuth information to an HTTP request. Depending on the <tt>options[:scheme]</tt> setting
        # this may add a header, additional query string parameters, or additional POST body parameters.
        # The default scheme is +header+, in which the OAuth parameters as put into the +Authorization+
        # header.
        #
        # This method also modifies the <tt>User-Agent</tt> header to add the OAuth gem version.
        #
        # See Also: {OAuth core spec version 1.0, section 5.4.1}[http://oauth.net/core/1.0#rfc.section.5.4.1]
        def oauth!(http, consumer, token = nil, options = {})
          options = { :request_uri      => expand_uri(http),
                      :consumer         => consumer,
                      :token            => token,
                      :scheme           => :header,
                      :signature_method => "HMAC-SHA1",
                      :nonce            => nil,
                      :timestamp        => nil }.merge(options || {})

          @oauth_helper = OAuth::Client::Helper.new(self, options)
          @oauth_helper.amend_user_agent_header(self)

          case options[:scheme].to_sym
          when :header
            set_oauth_header
          when :body
            set_oauth_body
          when :query_string
            set_oauth_query_string
          else
            raise OAuth::Error, "Unsupported scheme: #{options[:scheme]}"
          end
        end

        # Create a string suitable for signing for an HTTP request. This process involves parameter
        # normalization as specified in the OAuth specification. The exact normalization also depends
        # on the <tt>options[:scheme]</tt> being used so this must match what will be used for the request
        # itself. The default scheme is +header+, in which the OAuth parameters as put into the +Authorization+
        # header.
        #
        # See Also: {OAuth core spec version 1.0, section 9.1.1}[http://oauth.net/core/1.0#rfc.section.9.1.1]
        def signature_base_string(http, consumer, token = nil, options = {})
          options = { :request_uri      => expand_uri(http),
                      :consumer         => consumer,
                      :token            => token,
                      :scheme           => :header,
                      :signature_method => "HMAC-SHA1",
                      :nonce            => nil,
                      :timestamp        => nil }.merge(options || {})

          OAuth::Client::Helper.new(self, options).signature_base_string
        end

      private

        def expand_uri(http)
          uri = URI.parse(self.path)
          uri.host = http.address
          uri.port = http.port

          if http.respond_to?(:use_ssl?) && http.use_ssl?
            uri.scheme = "https"
          else
            uri.scheme = "http"
          end

          uri.to_s
        end

        def set_oauth_header
          self['Authorization'] = oauth_helper.header
        end

        # FIXME: if you're using a POST body and query string parameters, using this
        # method will convert those parameters on the query string into parameters in
        # the body. this is broken, and should be fixed.
        def set_oauth_body
          self.form_data = oauth_helper.form_data
        end

        def set_oauth_query_string
          self.path = oauth_helper.path(path)
        end
      end
    end
  end
end

Net::HTTPRequest.send(:include, OAuth::Client::Net::HTTPRequest)
