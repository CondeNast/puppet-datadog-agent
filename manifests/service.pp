# Class: datadog_agent::service
#
# This class declares the datadog-agent service
#

class datadog_agent::service(
  $service_ensure = 'running',
  $service_enable = true,
) inherits datadog_agent::params {

  validate_bool($service_enable)

  service { $datadog_agent::params::service_name:
    ensure    => $service_ensure,
    enable    => $service_enable,
    hasstatus => false,
    pattern   => 'dd-agent',
    require   => Package[$datadog_agent::params::package_name],
  }

}
