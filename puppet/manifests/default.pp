

node "admin" {

  service { "iptables":
    ensure => stopped
  }

  include ntpconfig

  include profile::weblogic::server::admin

  Service["iptables"] -> Class["ntpconfig"] -> Class["profile::weblogic::server::admin"]

}

node "managed01" {

  include ntpconfig

  service { "iptables":
    ensure => stopped
  }

  include profile::weblogic::server::managed


  Service["iptables"] -> Class["ntpconfig"] -> Class["profile::weblogic::server::managed"]

}

node "managed02" {

  include ntpconfig

  service { "iptables":
    ensure => stopped
  }

  include profile::weblogic::server::managed


  Service["iptables"] -> Class["ntpconfig"] -> Class["profile::weblogic::server::managed"]

}

class ntpconfig {

  class { '::ntp':
      servers => [ '192.168.33.1' ],
  }

}
