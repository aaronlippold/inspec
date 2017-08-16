require 'pry'
require 'utils/SimpleConfig'
require 'utils/parser'
class RsyslogConf < Inspec::resource(1)
  name 'rsyslog_conf'
  desc 'Use the rsyslog_conf InSpec audit resource '
  example "
  "

  # figure out which implementation it is using, sec/pwquality, or whatever.

  attr_reader :params

  def initialize(host_path = nil)
    return skip_resource 'The `rsyslog_conf` resource is not supported on your OS.' unless inspec.os.linux? || inspec.os.windows?
    @conf_path = host_path || '/etc/rsyslog.conf'
    @content = nil
    @params = nil
    read_content
  end

  def cron_logging?

  end

  private

  def read_content
    @content = ''
    @params = {}
    @content = read_file(@conf_path)
    @params = read_params(@content)
  end

  def read_params(content)
    # parse the file
    conf = SimpleConfig.new(
      content,
      assignment_regex: /^(\S*)\s*(\S*)\s*$/,
    )
    @params = conf.params
    binding.pry
  end

  def read_file(conf_path = @conf_path)
    file = inspec.file(conf_path)
    if !file.file?
      return skip_resource "Can't find file. \"#{@conf_path}\""
    end

    raw_conf = file.content
    if raw_conf.empty? && !file.empty?
      return skip_resource("File is empty.\"#{@conf_path}\"")
    end
    inspec.file(conf_path).content
  end
end
