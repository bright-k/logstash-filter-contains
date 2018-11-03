# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "set"

java_import 'java.util.concurrent.locks.ReentrantReadWriteLock'

class LogStash::Filters::CONTAINS < LogStash::Filters::Base

  config_name "contains"

  # The field(s) to check with. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "fruits" ]
  #         field => [ "%{a}" ]
  #         value => [ "apple" ]
  #       }
  #     }
  config :field, :validate => :array, :default => []

  # The value(s) to check against. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "fruits" ]
  #         field => [ "%{a}" ]
  #         value => [ "banana" ]
  #       }
  #     }
  config :value, :validate => :array, :default => []

  # The full path of the external file containing the value(s) to check against. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "fruits" ]
  #         field => [ "%{a}" ]
  #         value_path => "/etc/logstash/fruits"
  #       }
  #     }
  # NOTE: it is an error to specify both 'value' and 'value_path'.
  config :value_path, :validate => :path

  # When using a network list from a file, this setting will indicate
  # how frequently (in seconds) Logstash will check the file for
  # updates.
  config :refresh_interval, :validate => :number, :default => 600

  # The separator character used in the encoding of the external file
  # pointed by value_path.
  config :separator, :validate => :string, :default => "\n"

  public
  def register
    rw_lock = java.util.concurrent.locks.ReentrantReadWriteLock.new
    @read_lock = rw_lock.readLock
    @write_lock = rw_lock.writeLock

    if @value_path && !@value.empty? #checks if both value and value_path are defined in configuration options
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "contains",
        :error => "The configuration options 'value' and 'value_path' are mutually exclusive"
      )
    end

    if !@value.empty?
      @value_set = @value.to_set
    end

    if @value_path
      @next_refresh = Time.now + @refresh_interval
      lock_for_write { load_file }
    end
  end # def register

  def lock_for_write
    @write_lock.lock
    begin
      yield
    ensure
      @write_lock.unlock
    end
  end # def lock_for_write

  def lock_for_read #ensuring only one thread updates the network block list
    @read_lock.lock
    begin
      yield
    ensure
      @read_lock.unlock
    end
  end #def lock_for_read

  def needs_refresh?
    @next_refresh < Time.now
  end # def needs_refresh

  def load_file
    begin
      temporary = File.open(@value_path, "r") {|file| file.read.split(@separator)}
      if !temporary.empty? #ensuring the file was parsed correctly
        @value_set = temporary.to_set
      else
        @value_set = set
      end
    rescue
      if @value_set #if the list was parsed successfully before
        @logger.error("Error while opening/parsing the file")
      else
        raise LogStash::ConfigurationError, I18n.t(
          "logstash.agent.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "contains",
          :error => "The file containing the network list is invalid, please check the separator character or permissions for the file."
        )
      end
    end
  end #def load_file

  public
  def filter(event)
    field = @field.collect do |f|
      begin
        event.sprintf(f)
      rescue ArgumentError => e
        @logger.warn("Invalid field, skipping", :field => f, :event => event)
        nil
      end
    end
    field.compact!

    if @value_path #in case we are getting values from an external file
      if needs_refresh?
        lock_for_write do
          if needs_refresh?
            load_file
            @next_refresh = Time.now() + @refresh_interval
          end
        end #end lock
      end #end refresh from file
    end

    field.each do |f|
      @logger.debug("Checking value contains", :field => f, :value => @value_set)
      if @value_set.member?(f)
        filter_matched(event)
        return
      end
    end
  end # def filter
end # class LogStash::Filters::CONTAINS
