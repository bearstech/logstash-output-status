# encoding: utf-8
require 'logstash/outputs/base'
require 'logstash/namespace'
require 'puma/server'
require 'puma/minissl'
require 'base64'

class Puma::Server
  # ensure this method doesn't mess up our vanilla request
  def normalize_env(env, client); end
end

class LogStash::Outputs::Status < LogStash::Outputs::Base
  attr_accessor :lastbeat

  config_name 'status'

  # The host or ip to bind
  config :host, validate: :string, default: '0.0.0.0'

  # The TCP port to bind to
  config :port, validate: :number, default: 8080

  # Maximum number of threads to use
  config :threads, validate: :number, default: 4

  # Username for basic authorization
  config :user, validate: :string, required: false

  # Password for basic authorization
  config :password, validate: :password, required: false

  # SSL Configurations
  #
  # Enable SSL
  config :ssl, validate: :boolean, default: false

  # The JKS keystore to validate the client's certificates
  config :keystore, validate: :path

  # Set the truststore password
  config :keystore_password, validate: :password

  # useless headers puma adds to the requests
  # mostly due to rack compliance
  REJECTED_HEADERS = ['puma.socket', 'rack.hijack?', 'rack.hijack', 'rack.url_scheme', 'rack.after_reply', 'rack.version', 'rack.errors', 'rack.multithread', 'rack.multiprocess', 'rack.run_once', 'SCRIPT_NAME', 'QUERY_STRING', 'SERVER_PROTOCOL', 'SERVER_SOFTWARE', 'GATEWAY_INTERFACE']

  RESPONSE_HEADERS = { 'Content-Type' => 'application/json' }

  public

  def register
    @mutex = Mutex.new
    @lastbeat = {}
    @server = ::Puma::Server.new(nil) # we'll set the rack handler later
    if @user && @password
      token = Base64.strict_encode64("#{@user}:#{@password.value}")
      @auth_token = "Basic #{token}"
    end
    if @ssl
      if @keystore.nil? || @keystore_password.nil?
        fail(LogStash::ConfigurationError, 'Settings :keystore and :keystore_password are required because :ssl is enabled.')
      end
      ctx = Puma::MiniSSL::Context.new
      ctx.keystore = @keystore
      ctx.keystore_pass = @keystore_password.value
      @server.add_ssl_listener(@host, @port, ctx)
    else
      @server.add_tcp_listener(@host, @port)
    end
    @server.min_threads = 0
    @server.max_threads = @threads

    # proc needs to be defined at this context
    # to capture @codecs, @logger and lowercase_keys
    p = proc do |req|
      begin
        remote_host = req['puma.socket'].peeraddr[3]
        REJECTED_HEADERS.each { |k| req.delete(k) }
        body = req.delete('rack.input')
        last = @lastbeat.clone
        last['@delta'] = Time.new - last['@timestamp'].time
        ['200', RESPONSE_HEADERS, [last.to_json]]
      rescue => e
        @logger.error("unable to process event #{req.inspect}. exception => #{e.inspect}")
        ['500', RESPONSE_HEADERS, ['internal error']]
      end
    end

    auth = proc do |username, password|
      username == @user && password == @password.value
    end if @user && @password

    @server.app = Rack::Builder.new do
      use(Rack::Auth::Basic, &auth) if auth
      run(p)
    end
    @server.run
  end # def register

  public

  def receive(_event)
    'Event received'
    @mutex.synchronize do
      @lastbeat = _event
    end
  end # def receive

  public

  def close
    return unless @server
    @server.stop(true)
    @server.binder.close if @server.binder
  rescue IOError
    # do nothing
  end # def close
end # class LogStash::Outputs::Status
