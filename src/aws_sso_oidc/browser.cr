module AwsSsoOidc
  def self.open_browser(url : String) : Nil
    {% if flag?(:darwin) %}
      Process.run("open", [url])
    {% else %}
      Process.run("xdg-open", [url])
    {% end %}
  rescue
    nil
  end
end
