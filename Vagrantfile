# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
    config.cache.enable :yum
  end

  config.vm.synced_folder ".", "/vagrant", :mount_options => ["dmode=777","fmode=777"]

  if Vagrant.has_plugin?("vagrant-proxyconf")
    config.proxy.http     = "http://192.168.33.1:3128/"
    config.proxy.https    = "http://192.168.33.1:3128/"
    config.proxy.no_proxy = "localhost,127.0.0.1,.example.com"
  end

  config.vm.box = "puppetlabs/centos-6.6-64-puppet"
  config.vm.box_version = '1.0.1'

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 1
    vb.memory = 1536
  end

  config.vm.define "db" do |v|
    v.vm.host_name = "db"
    v.vm.network "private_network", ip: "192.168.33.9"
    v.vm.provider "virtualbox" do |vb|
      vb.cpus = "2"
      vb.memory = "2048"
    end
  end

  # config.vm.define "admin" do |v|
  #   v.vm.host_name = "admin"
  #   v.vm.network "private_network", ip: "192.168.33.10"
  # end

  #config.vm.define "managed01" do |v|
  #  v.vm.host_name = "managed01"
  #  v.vm.network "private_network", ip: "192.168.33.11"
  #end

  # config.vm.define "managed02" do |v|
  #   v.vm.host_name = "managed02"
  #   v.vm.network "private_network", ip: "192.168.33.12"
  # end

  config.vm.provision "shell", inline: <<-SHELL
    # yum install http://yum.puppetlabs.com/puppetlabs-release-el-6.noarch.rpm -y
    # yum install puppet -y
    # yum install libaio bc flex -y
    # yum install /vagrant/oracle-xe-11.2.0-1.0.x86_64.rpm -y
    # /etc/init.d/oracle-xe configure responseFile=/vagrant/xe.rsp
  SHELL

  config.vm.provision :puppet do |puppet|
    puppet.module_path = "puppet/modules"
    puppet.manifests_path = "puppet/manifests"
    puppet.hiera_config_path = "puppet/hiera.yaml"
    puppet.options = '--debug --trace --profile --verbose'
  end
end
