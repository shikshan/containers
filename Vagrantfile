# -*- mode: ruby -*-
# vi: set ft=ruby :

### Make sure guest addtions plugin is installed - `vagrant plugin install vagrant-vbguest`
### If the guest additions are not installed successfully in the first run of `vagrant up`, do it manually
### `vagrant vbguest --do install`

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/31-cloud-base"
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"
end
