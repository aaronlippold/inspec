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
    @rules = []
    @templates = []
    @directives = []
    read_content
  end

  def rules
    RsyslogRules.new(@rules)
  end

  def templates
    RsyslogTemplates.new(@templates)
  end

  def global_directives
    RsyslogGlobalDirectives.new(@directives)
  end

  private

  def read_content
    @content = ''
    @params = {}
    @content = read_file(@conf_path)
    @params = parse_conf(@content)
  end

  def parse_conf(content)
    line_continue = false
    last_line = ''
    content.map.with_index do |line, i|
      data, = parse_comment_line(line, comment_char: '#', standalone_comments: false)
      if line[-2] == '\'' || content[i+1][0] == '&'
        line_continue = true
        last_line = last_line + data
      else
        last_continue = false
        parse_line(last_line + data)
        last_line = ''
      end
    end.compact
  end

  def parse_line(line)
    if line[0] != '$'
      @rules.push(parse_rule(line))
    elsif line.split[0] == '$template'
      @templates.push(parse_template(line))
    else
      @directives.push(parse_global_directive(line))
    end
  end

  def parse_rule(line)
    if line.split[0] == 'if'
      parts = line.split("then")
      {
        'selectors' => parts[0],
        'actions' => parts[1],
      }
    elsif line[0] == ':'
      parts = line.split(',')
      {
        'selectors' => {
          'property' => parts[0][1..-1],
          'compare-operation' => parts[1],
          'value' => parts[2].split(/".*"/)[0],
        },
        'actions' => parts[2].split(/".*"/)[1],
      }
    else
      parts = line.split
      {
        'selectors' => parts[0].split(";"),
        'actions' => parts[1],
      }
    end
  end

  def parse_global_directive(line)
    {
      'name' => line.split[0],
      'value' => line.split[1],
    }
  end

  def parse_template(line)
    parts = line.split(',')
    {
      'name' =>    parts[0].split[1],
      'text' =>    parts[1],
      'options' => parts[2],
    }
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
    inspec.file(conf_path).content.lines
  end

  class RsyslogRules
    # use filtertable for containers
    filter = FilterTable.create
    filter.add_accessor(:where)
          .add_accessor(:entries)
          .add(:selectors,  field: 'selectors')
          .add(:actions,    field: 'actions')

    filter.connect(self, :rules)

    attr_reader :rules
    def initialize(containers)
      @rules = rules
    end
  end

  class RsyslogTemplates
    # use filtertable for containers
    filter = FilterTable.create
    filter.add_accessor(:where)
          .add_accessor(:entries)
          .add(:name,  field: 'name')
          .add(:text,  field: 'text')
          .add(:options,  field: 'options')

    filter.connect(self, :rules)

    attr_reader :rules
    def initialize(rules)
      @rules = rules
    end
  end

  class RsyslogGlobalDirectives
    # use filtertable for containers
    filter = FilterTable.create
    filter.add_accessor(:where)
          .add_accessor(:entries)
          .add(:name,  field: 'name')
          .add(:value,    field: 'value')

    filter.connect(self, :directives)

    attr_reader :directives
    def initialize(directives)
      @rules = directives
    end
  end
end
