# Class: datadog_agent::integrations::tcp_check
#
# This class will install the necessary config to hook the tcp_check in the agent
#
# Parameters:
#   checkname
#       (Required) The name of the instance.
#
#   host
#       (Required) The hostname/ip to check.
#
#   port
#       (Required) This port to check.
#
#   timeout
#       The (optional) timeout in seconds.
#
#   threshold
#   window
#       The (optional) window and threshold parameters allow you to trigger
#       alerts only if the check fails x times within the last y attempts
#       where x is the threshold and y is the window.
#
#   collect_response_time
#       The (optional) collect_response_time parameter will instruct the
#       check to create a metric 'network.http.response_time', tagged with
#       the url, reporting the response time in seconds.
#
#   skip_event
#       The (optional) skip_event parameter will instruct the check to not
#       create any event to avoid duplicates with a server side service check.
#       This defaults to True because this is being deprecated.
#       (See https://github.com/DataDog/dd-agent/blob/master/checks/network_checks.py#L178-L180)
#
#   tags
#       The (optional) tags to add to the check instance.
#
# Sample Usage:
#
# Add a class for each check instance:
#
# class { 'datadog_agent::integrations::tcp_check':
#   checkname => 'LDAP 389',
#   host      => '127.0.0.1',
#   port      => '389',
# }
#
# class { 'datadog_agent::integrations::tcp_check':
#   checkname => 'LDAP 636',
#   host      => '127.0.0.1',
#   port      => '636',
#   tags      => ['production', 'wordpress'],
# }
#
# class { 'datadog_agent::integrations::tcp_check':
#   checkname             => 'localhost-9001',
#   host                  => 'localhost',
#   port                  => '9001',
#   timeout               => 5,
#   threshold             => 1,
#   window                => 1,
#   collect_response_time => true,
#   tags                  => 'production',
# }
#
#
# Add multiple instances in one class declaration:
#
#  class { 'datadog_agent::integrations::tcp_check':
#        instances => [{
#          'checkname' => 'ldap 389',
#          'host'      => 'localhost',
#          'port'      => '389',
#        },
#        {
#          'checkname' => 'ldap 636',
#          'host'      => 'localhost',
#          'port'      => '389',
#          'tags'      => ['production', 'wordpress'],
#        }]
#     }


class datadog_agent::integrations::tcp_check (
  $checkname             = undef,
  $host                  = undef,
  $port                  = undef,
  $timeout               = 1,
  $threshold             = undef,
  $window                = undef,
  $collect_response_time = true,
  $skip_event            = true,
  $tags                  = [],
  $instances             = undef,
) inherits datadog_agent::params {
  include datadog_agent

  if !$instances and $host {
    $_instances = [{
      'checkname'             => $checkname,
      'host'                  => $host,
      'port'                  => $port,
      'timeout'               => $timeout,
      'threshold'             => $threshold,
      'window'                => $window,
      'collect_response_time' => $collect_response_time,
      'skip_event'            => $skip_event,
      'tags'                  => $tags,
    }]
  } elsif !$instances{
    $_instances = []
  } else {
    $_instances = $instances
  }

  $legacy_dst = "${datadog_agent::params::legacy_conf_dir}/tcp_check.yaml"
  if $::datadog_agent::_agent_major_version > 5 {
    $dst_dir = "${datadog_agent::params::conf_dir}/tcp_check.d"
    file { $legacy_dst:
      ensure => 'absent'
    }

    file { $dst_dir:
      ensure  => directory,
      owner   => $datadog_agent::params::dd_user,
      group   => $datadog_agent::params::dd_group,
      mode    => $datadog_agent::params::permissions_directory,
      require => Package[$datadog_agent::params::package_name],
      notify  => Service[$datadog_agent::params::service_name]
    }
    $dst = "${dst_dir}/conf.yaml"
  } else {
    $dst = $legacy_dst
  }

  file { $dst:
    ensure  => file,
    owner   => $datadog_agent::params::dd_user,
    group   => $datadog_agent::params::dd_group,
    mode    => $datadog_agent::params::permissions_protected_file,
    content => template('datadog_agent/agent-conf.d/tcp_check.yaml.erb'),
    require => Package[$datadog_agent::params::package_name],
    notify  => Service[$datadog_agent::params::service_name]
  }
}
