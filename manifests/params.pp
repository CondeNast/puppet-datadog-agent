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

  case $::operatingsystem {
    'Ubuntu','Debian' : {
      $rubydev_package   =  'ruby-dev'
    }
    'RedHat','CentOS','Fedora','Amazon','Scientific' : {
      $rubydev_package   = 'ruby-devel'
    }
    default: { fail("Class[datadog_agent]: Unsupported operatingsystem: ${::operatingsystem}") }
  }

  user { 'create-dd-agent-user':
    name    => "$dd_user",
    ensure  => 'present',
    gid     => 'root',
    groups  => ['dd-agent', 'docker']
  }

  group { 'create-docker-group':
    name    => 'docker',
    gid     => '500',
    ensure  => 'present',
    before  => User['create-dd-agent-user']
  }

  group { 'create-dd-agent-group':
    name    => 'dd-agent',
    gid     => '501',
    ensure  => 'present',
    before  => User['create-dd-agent-user']
  }

}
