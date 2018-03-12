# Net Actuate Ansible modules

This page explains, by example, how to use the Net Actuate Ansible Modules.
The examples here will use sub-folders in the users $HOME folder.

*Note: These modules are not yet included with Ansible so need to be accessed
as custom modules.  
This means that you need to have an ENV variable set named "ANSIBLE_LIBRARY"
to some folder on your system and then git clone this repo into that folder.*

## Set up your environment to use these modules

### Make a new folder to hold custom Ansible modules

```bash
mkdir $HOME/ansible-modules
```

### Set up your shell environment with two required variables

```bash
# Set your API key
export HOSTVIRTUAL_API_KEY=<YOUR HV API KEY>

# Make sure this module gets included
export ANSIBLE_LIBRARY=$HOME/ansible-modules
```

### Create a virtualenv for use with Ansible

```bash
virtualenv $HOME/ansible-venv
```

### Load the virtualenv

```bash
. $HOME/ansible-venv/bin/activate
```

### Git clone this repo into the ansible-modules folder and cd to it

```bash
cd $HOME/ansible-modules
git clone git@gl.vr.org:/napublic/na-ansible-modules
cd na-ansible-modules
```

### Pull in requirements

```bash
pip install -r requirements.txt
```

# Using the modules

## Example Role and inventory files

### Role file

```yaml
# file: roles/install/tasks/main.yml
- name: install
  na_compute_node:
    hostname: "{{ inventory_hostname }}"
    ssh_public_key: "{{ ssh_public_key }}"
    operating_system: "{{ operating_system }}"
    mbpkgid: "{{ mbpkgid }}"
    state: "{{ state }}"
  register: hostvirtual_device_result
  delegate_to: localhost
```

### Inventory file

```ini
[all]
host1.example.com ssh_public_key=keys.pub operating_system='Debian 9.0 x64 PV' mbpkgid=5551212 location='RDU3 - Raleigh, NC'
```
