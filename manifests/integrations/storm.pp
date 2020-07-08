# Class: datadog_agent::integrations::storm
#
#
# Parameters:
#  server 
#       (Required) The name of the instance.
#


class datadog_agent::integrations::storm(
  $server      = 'http://localhost:8080',
  $environment = $::environment,
) inherits datadog_agent::params {
  include datadog_agent

  notify {"Running DataDog Storm integration with \$agent_major_version set to ${agent_major_version}, \$_agent_major_version set to ${_agent_major_version} and \$agent_version set to ${agent_version}":}

  $legacy_dst_yaml = "${datadog_agent::params::legacy_conf_dir}/storm.yaml"
  if $::datadog_agent::_agent_major_version > 5 {
    $dst_dir = "${datadog_agent::params::conf_dir}/storm.d"
    file { $legacy_dst_yaml:
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
    $dst_yaml = "${dst_dir}/conf.yaml"
    $dst_check = ${datadog_agent::params::checks_dir}/storm.py
  } else {
    $dst_yaml = $legacy_dst_yaml
    $dst_check = ${datadog_agent::params::legacy_checks_dir}/storm.py
  }

  file { "$dst_check":
    ensure  => file,
    owner   => $datadog_agent::params::dd_user,
    group   => $datadog_agent::params::dd_group,
    mode    => $datadog_agent::params::permissions_protected_file,
    source  => 'puppet:///modules/datadog_agent/checks.d/storm.py',
    require => Package[$datadog_agent::params::package_name],
    notify  => Service[$datadog_agent::params::service_name],
  }

  file { $dst_yaml:
    ensure  => file,
    owner   => $datadog_agent::params::dd_user,
    group   => $datadog_agent::params::dd_group,
    mode    => $datadog_agent::params::permissions_protected_file,
    content => template('datadog_agent/agent-conf.d/storm.yaml.erb'),
    require => Package[$datadog_agent::params::package_name],
    notify  => Service[$datadog_agent::params::service_name],
  }
}
