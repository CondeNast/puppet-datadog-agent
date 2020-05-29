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

#  $dd_group       = 'root'

# Used for legacy storm integration
  $checks_dir     = '/etc/dd-agent/checks.d'

  $datadog_site                   = 'datadoghq.com'
  $dd_groups                      = undef
  $default_agent_major_version    = 5
  $agent_version                  = 'latest'
  $dogapi_version                 = 'installed'
  $gem_provider                   = 'puppetserver_gem'
  $conf_dir_purge                 = false
  $apt_default_release            = 'stable'
  $apm_default_enabled            = false
  $process_default_enabled        = false
  $process_default_scrub_args     = true
  $process_default_custom_words   = []
  $logs_enabled                   = false
  $logs_open_files_limit          = undef
  $container_collect_all          = false
  $use_apt_backup_keyserver       = false
  $apt_backup_keyserver           = 'hkp://pool.sks-keyservers.net:80'
  $apt_keyserver                  = 'hkp://keyserver.ubuntu.com:80'
  $sysprobe_service_name          = 'datadog-agent-sysprobe'

  case $::operatingsystem {
    'Ubuntu','Debian' : {
      $rubydev_package            = 'ruby-dev'
      $legacy_conf_dir            = '/etc/dd-agent/conf.d'
      $conf_dir                   = '/etc/datadog-agent/conf.d'
      $dd_user                    = 'dd-agent'
      $dd_group                   = 'dd-agent'
      $service_name               = 'datadog-agent'
      $agent_log_file             = '/var/log/datadog/agent.log'
      $package_name               = 'datadog-agent'
      $permissions_directory      = '0755'
      $permissions_file           = '0644'
      $permissions_protected_file = '0600'
      $agent_binary               = '/opt/datadog-agent/bin/agent/agent'
    }
    'RedHat','CentOS','Fedora','Amazon','Scientific','OracleLinux' : {
      $rubydev_package            = 'ruby-devel'
      $legacy_conf_dir            = '/etc/dd-agent/conf.d'
      $conf_dir                   = '/etc/datadog-agent/conf.d'
      $dd_user                    = 'dd-agent'
      $dd_group                   = 'dd-agent'
      $service_name               = 'datadog-agent'
      $agent_log_file             = '/var/log/datadog/agent.log'
      $package_name               = 'datadog-agent'
      $permissions_directory      = '0755'
      $permissions_file           = '0644'
      $permissions_protected_file = '0600'
      $agent_binary               = '/opt/datadog-agent/bin/agent/agent'
    }
    default: { fail("Class[datadog_agent]: Unsupported operatingsystem: ${::operatingsystem}") }
  }

}
