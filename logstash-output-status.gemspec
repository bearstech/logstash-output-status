Gem::Specification.new do |s|
  s.name          = 'logstash-output-status'
  s.version       = "0.1.2"
  s.licenses      = ["Apache License (2.0)"]
  s.summary       = "Http output status for monitoring"
  s.description   = ""
  s.authors       = ["athoune"]
  s.email         = "mlecarme@bearstech.com"
  s.homepage      = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths = ["lib"]

  # Files
  s.files         = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec',
                        '*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata      = { "logstash_plugin" => "true",
                      "logstash_group" => "output" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", ">= 2.0.0", "< 3.0.0"
  s.add_runtime_dependency "logstash-codec-plain"
  s.add_runtime_dependency 'puma', '~> 2.11.3'

  s.add_development_dependency "logstash-devutils"
end
