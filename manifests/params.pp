# Class: datadog_agent::params
#
# This class contains the parameters for the Datadog module
#
# Parameters:
#   $api_key:
#       Your DataDog API Key. Please replace with your key value
#   $dd_url
#       The URL to the DataDog application.
#
# Actions:
#
# Requires:
#
# Sample Usage:
#
class datadog_agent::params {
  $conf_dir       = '/etc/dd-agent/conf.d'
  $dd_user        = 'dd-agent'
  $dd_group       = 'root'
  $package_name   = 'datadog-agent'
  $service_name   = 'datadog-agent'
  $checks_dir     = '/etc/dd-agent/checks.d'

  $process_default_scrub_args   = true
  $process_default_custom_words = []
  $logs_enabled                 = false
  $logs_open_files_limit        = undef
  $container_collect_all        = false
  $legacy_conf_dir              = '/etc/dd-agent/conf.d'
  $conf_dir                     = '/etc/datadog-agent/conf.d'
  $conf_dir_purge                 = false
  $datadog_site                   = 'datadoghq.com'
  $agent_log_file             = '/var/log/datadog/agent.log'

  case $::operatingsystem {
    'Ubuntu','Debian' : {
      $rubydev_package   =  'ruby-dev'
    }
    'RedHat','CentOS','Fedora','Amazon','Scientific' : {
      $rubydev_package   = 'ruby-devel'
    }
    default: { fail("Class[datadog_agent]: Unsupported operatingsystem: ${::operatingsystem}") }
  }

}
