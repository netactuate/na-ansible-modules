#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2018, Dennis Durling <djdtahoe@gmail.com>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: na_compute_node
version_added: '2.6.0'
short_description: Manage virtual machines on NetActuate infrastructure.
description:
    - Deploy newly purchaced packages.
    - Build, destroy, start and stop previously built packages.
author: "Dennis Durling (@tahoe)"
options:
  name:
    description:
      - Hostname of the node.
      - Required.
  ssh_public_key:
    description:
      - Path to the ssh key that will be used for node authentication.
      - Required and currently the only method of authentication for the node.
      - NOTE: At some point we will set up password authentication here.
  operating_system:
    description:
      - Either the ID or full name of the OS to be installed on the node.
      - Required.
      - NOTE: to many choices to list here. will provide a method for customers
        to figure out which one they want.
  mbpkgid:
    description:
      - The purchased package ID the node is associated with.
      - Required as purchasing new nodes is not yet available here.
  state:
    description:
      - Desired state of the instance.
    choices: [ present, running, stopped, absent ]
  location:
    description:
      - Name or id of physical location the node should be built in.
      - Required.
      - Note: Currently once this is set it cannot be changed from ansible.
'''

EXAMPLES = '''
# NOTE: State should be defined in a playbook but can also be overridden here
#       all other values should probably be stated as variables in inventory.
- name: Change state of a package
  hv_compute_node:
    hostname: "{{ inventory_hostname }}"
    ssh_public_key: "{{ ssh_public_key }}"
    operating_system: "{{ operating_system }}"
    mbpkgid: "{{ mbpkgid }}"
    state: "{{ running }}"
  register: hostvirtual_device_result
  delegate_to: localhost

# NOTE: Example inventory file.
host1.example.com ssh_public_key=keys.pub operating_system='Debian 9.0 x64 PV'\
mbpkgid=5551212 location='RDU3 - Raleigh, NC'
'''

RETURN = '''
Standard represenation for a device as returned by various tasks::

    {
        'id': 'device_id'
        'hostname': 'device_hostname',
        'state': 'device_state',
        'ip_addresses': [
            {
                "address": "8.8.8.8",
                "address_family": 4,
                "public": true
            },
            {
                "address": "::1",
                "address_family": 6,
                "public": true
            },
            {
                "address": "10.100.11.129",
                "address_family": 4,
                "public": false
            }
        ],
        "private_ipv4": "10.100.11.129",
        "public_ipv4": "8.8.8.8",
        "public_ipv6": "::1",
    }
'''

import time
import os
import re
import json
from libcloud.compute.base import NodeAuthSSHKey
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from ansible.module_utils.basic import AnsibleModule

HOSTVIRTUAL_API_KEY_ENV_VAR = "HOSTVIRTUAL_API_KEY"

NAME_RE = '({0}|{0}{1}*{0})'.format('[a-zA-Z0-9]', r'[a-zA-Z0-9\-]')
HOSTNAME_RE = r'({0}\.)*{0}$'.format(NAME_RE)
MAX_DEVICES = 100

ALLOWED_STATES = ['building', 'pending', 'running', 'stopping', 'present',
                  'rebooting', 'starting', 'absent', 'stopped']

# until the api gets fixed so it's more flexible
API_ROOT = ''


###
#
# Section: Helper functions
#
##
def _get_valid_hostname(module):
    """The user will set the hostname so we have to check if it's valid
    hostname:   string of an intended hostname
    Returns:
        Bool
    """
    hostname = module.params.get('hostname')
    if re.match(HOSTNAME_RE, hostname) is None:
        module.fail_json(msg="Invalid hostname: {0}"
                         .format(module.params.get('hostname')))
        raise Exception("Invalid hostname: {0}".format(hostname))
    return hostname


def _get_ssh_auth(module):
    try:
        ssh_key = module.params.get('ssh_public_key')
        key = open(ssh_key).read()
        auth = NodeAuthSSHKey(pubkey=key)
        return auth.pubkey
    except Exception as e:
        module.fail_json(msg="Could not load ssh_public_key for {0},"
                         "Error was: {1}"
                         .format(module.params.get('hostname'), str(e)))


def _serialize_device(module, device):
    """Returns a json object describing the node as shown above in RETURN"""
    device_data = {}
    device_data['id'] = device.uuid
    device_data['hostname'] = device.name
    device_data['state'] = device.state
    device_data['ip_addresses'] = []
    for addr in device.public_ips:
        device_data['ip_addresses'].append(
            {
                'address': addr,
                'address_family': 4,
                'public': True
            }
        )
    for addr in device.private_ips:
        device_data['ip_addresses'].append(
            {
                'address': addr,
                'address_family': 4,
                'public': False
            }
        )
    # Also include each IPs as a key for easier lookup in roles.
    # Key names:
    # - public_ipv4
    # - public_ipv6
    # - private_ipv4
    # - private_ipv6 (if there is one)
    for ipdata in device_data['ip_addresses']:
        if ipdata['public']:
            if ipdata['address_family'] == 6:
                device_data['public_ipv6'] = ipdata['address']
            elif ipdata['address_family'] == 4:
                device_data['public_ipv4'] = ipdata['address']
        elif not ipdata['public']:
            if ipdata['address_family'] == 6:
                device_data['private_ipv6'] = ipdata['address']
            elif ipdata['address_family'] == 4:
                device_data['private_ipv4'] = ipdata['address']
    return device_data


def _get_location(module, avail_locs):
    """Check if a location is allowed/available

    Raises an exception if we can't use it
    Returns a location object otherwise
    """
    loc_arg = module.params.get('location')
    location = None
    loc_possible_list = [loc for loc in avail_locs
                         if loc.name == loc_arg or loc.id == loc_arg]

    if not loc_possible_list:
        _msg = "Image '%s' not found" % loc_arg
        module.fail_json(msg=_msg)
    else:
        location = loc_possible_list[0]
    return location


def _get_os(module, avail_oses):
    """Check if provided os is allowed/available

    Raises an exception if we can't use it
    Returns an image/OS object otherwise
    """
    os_arg = module.params.get('operating_system')
    image = None
    os_possible_list = [os for os in avail_oses
                        if os.name == os_arg or os.id == os_arg]

    if not os_possible_list:
        _msg = "Image '%s' not found" % os_arg
        module.fail_json(msg=_msg)
    else:
        image = os_possible_list[0]
    return image


def _get_node_stub(module=None, hv_conn=None, node_id=None):
    """Just try to get the node, otherwise return failure"""
    node_stub = None
    try:
        node_stub = hv_conn.ex_get_node(node_id)
    except Exception as e:
        module.fail_json(msg="Failed to get node {0}"
                         "with error: {1}"
                         .format(module.params.get('hostname'), str(e)))
    return node_stub


def _wait_for_state(
            module=None, hv_conn=None, node_id=None,
            timeout=600, interval=10.0,
            desired_state=None
        ):
    """Called after do_build_node to wait to make sure it built OK
    Arguments:
        hv_conn:            object  libcloud connectionCls
        node_id:            int     ID of node
        timeout:            int     timeout in seconds
        interval:           float   sleep time between loops
        desired_state:      string  string of the desired state
    """
    try_node = None
    for i in range(0, timeout, int(interval)):
        try:
            try_node = hv_conn.ex_get_node(node_id)
            if try_node.state == desired_state:
                break
        except Exception as e:
            module.fail_json(msg="Somehow failed to get node {0} for checking"
                             "state. Got error: {1}"
                             .format(module.params.get('hostname'), str(e)))
        time.sleep(interval)
    return try_node

###
#
# End Section: Helper functions
#
##


###
#
# Section: do_<action>_node functions
#
# this includes do_build_node, do_stop_node, do_start_node
# and do_delete_node, and any others we need later but these
# should cover it for now
#
# All these functions are called from within an ensure_node_<state> functions
# and perform the actual state changing work on the node
#
###
def do_build_new_node(module, hv_conn, h_parms):
    """Build nodes that have never been built"""
    # set up params to build the node
    params = {
        'mbpkgid': h_parms['mbpkgid'],
        'image': h_parms['image'].id,
        'fqdn': h_parms['hostname'],
        'location': h_parms['location'].id,
        'ssh_key': h_parms['ssh_key']
    }

    # do it using the api
    try:
        hv_conn.connection.request(
                    API_ROOT + '/cloud/server/build',
                    data=json.dumps(params),
                    method='POST'
                ).object
    except Exception as e:
        module.fail_json(msg="Failed to build node for node {0} with: {1}"
                         .format(h_parms['hostname'], str(e)))

    # get the new version of the node, hopefully showing
    # using wait_for_build_complete defauilt timeout (10 minutes)
    node = _wait_for_state(
        module=module,
        hv_conn=hv_conn,
        node_id=h_parms['mbpkgid'],
        desired_state='running'
    )
    changed = True
    return changed, node


def do_build_absent_node(module, hv_conn, node_stub, h_parms):
    """Build nodes that have been uninstalled

    NOTE: leaving here in case I need some code from here...
    """

    # set up params to build the node
    params = {
        'mbpkgid': node_stub.id,
        'image': h_parms['image'].id,
        'fqdn': h_parms['hostname'],
        'location': node_stub.extra['location'],
        'ssh_key': h_parms['ssh_key']
    }

    # do it using the api
    try:
        hv_conn.connection.request(
                    API_ROOT + '/cloud/server/build',
                    data=json.dumps(params),
                    method='POST'
                ).object
    except Exception:
        _msg = "Failed to build node for mbpkgid {0}".format(node_stub.id)
        raise Exception(_msg)

    # get the new version of the node, hopefully showing
    # that it's built and all that

    # get the new version of the node, hopefully showing
    # using wait_for_build_complete defauilt timeout (10 minutes)
    node = _wait_for_state(
        module=module,
        hv_conn=hv_conn,
        node_id=h_parms['mbpkgid'],
        desired_state='running'
    )
    changed = True
    return changed, node

###
#
# End Section: do_<action>_node functions
#
###


###
#
# Section: ensure_<state> functions
#
# all will build a node if it has never been built.
# the oddest case would be ensure_absent (uninstalled) where the node
# has never been built. This would require building, which will create the node
# on disk and then do a terminate call since we don't have a "setup_node"
# type api call that configures the node, get's it's IP, sets up which dom0 it
# should be on and whatnot.
#
###
def ensure_node_running(
            module=None, hv_conn=None,
            node_stub=None, h_parms=None
        ):
    """Called when we want to just make sure the node is running"""
    changed = False
    node = node_stub
    if node.state != 'running':
        # first build the node if it is in state 'absent'
        if node.state == 'absent':
            # do_build_absent_node handles waiting for it to finish
            # also note, this call should start it so we don't need to
            # do it again below
            changed, node = do_build_absent_node(
                    hv_conn, node_stub, h_parms
            )
        else:
            # node is installed so boot it up.
            running = hv_conn.connection.ex_start_node(h_parms['mbpkgid'])
            # if we don't get a positive response we need to bail
            if not running:
                raise Exception("Seems we had trouble starting the node")
            else:
                # Seems our command executed successfully
                # so wait for it to come up.
                node = _wait_for_state(
                    module=module,
                    hv_conn=hv_conn,
                    node_id=node.id,
                    desired_state='running',
                    timeout=30,
                    interval=10.0
                )
                changed = True
    return changed, node


def ensure_node_stopped(module=None, hv_conn=None, node_stub=None):
    """Called when we want to just make sure that a node is NOT running
    """
    changed = False
    node = node_stub
    if node.state != 'stopped':
        stopped = hv_conn.ex_stop_node(node_stub)
        if not stopped:
            raise Exception("Seems we had trouble stopping the node")
        else:
            # wait for the node to say it's stopped.
            node = _wait_for_state(
                module=module,
                hv_conn=hv_conn,
                node_id=node.id,
                desired_state='stopped',
                timeout=30,
                interval=10.0
            )
            changed = True
    return changed, node


def ensure_node_present(
            module=None, hv_conn=None,
            node_stub=None, h_parms=None
        ):
    """Called when we want to just make sure that a node is NOT absent
    """
    # default state
    changed = False
    node = node_stub

    # only do anything if the node.state == 'absent'
    # default is to leave 'changed' as False and return it and the node.
    if node.state == 'absent':
        # otherwise,,, build the node.
        changed, node = do_build_absent_node(
            module, hv_conn, node_stub, h_parms
        )
    return changed, node


def ensure_node_absent(module=None, hv_conn=None, node_stub=None):
    """Ensure the node is not installed, uninstall it if it is installed
    """
    # default return values
    changed = False
    node = node_stub

    # uninstall the node if it is not showing up as absent.
    if node.state != 'absent':
        # uninstall the node
        try:
            deleted = hv_conn.ex_delete_node(node=node)
        except Exception as e:
            module.fail_json(msg="Failed to call delete node on {0},"
                             "with error: {1}"
                             .format(module.params.get('hostname'), str(e)))
        if not deleted:
            module.fail_json(msg="Seems we had trouble deleting the node {0}"
                             .format(module.params.get('hostname')))
        else:
            # wait for the node to say it's absent
            node = _wait_for_state(
                module=module,
                hv_conn=hv_conn,
                node_id=node.id,
                desired_state='termindated',
                timeout=30,
                interval=10.0
            )
            changed = True
    return changed, node

###
#
# End Section: ensure_node_<state> functions
#
###


###
#
# Section: Main functions
#
# includes the main() and ensure_state() functions
#
# the main function starts everything off and the
# ensure_state() function which handles the logic for deciding which
# ensure_node_<state> function to call and what to pass it.
# mainly to keep main() clean and simple.
#
###
def ensure_state(
            desired_state='running',
            module=None,
            hv_conn=None,
            h_parms=None
        ):
    """Main function call that will check desired state
    and call the appropriate function and handle the respones back to main.

    The called functions will check node state and call state altering
    functions as needed.
    """
    # set default changed to False
    changed = False
    # TRY to get the node from the mbpkgid provided (required)
    # Everything else we call MUST account for node_stub being None.
    # node_stub being None indicates it has never been built.
    node_stub = _get_node_stub(
        module=module, hv_conn=hv_conn,
        node_id=h_parms['mbpkgid']
    )

    ###
    # DIE if the node has never been built and we are being asked to uninstall
    # we can't uninstall the OS on a node that isn't even in the DB
    ###
    if not node_stub and desired_state == 'absent':
        module.fail_json(msg="Cannot terminate a node that doesn't exist."
                         "Please build the package first,"
                         "then you can uninstall it.")

    # We only need to do any work if the below conditions exist
    # otherwise we will return the defaults
    if node_stub is None or node_stub.state != desired_state:
        # main block here, no else as we would just return
        # build the node if it doesn't exist
        # tmp_changed is mainly for 'running' check below since building
        # a new node will put it in a 'running' state and we want to indicates
        # that it has changed (since it was built)
        if node_stub is None:
            # all  states require the node to be installed so do that first.
            tmp_changed, node_stub = do_build_new_node(
                module=module, hv_conn=hv_conn, h_parms=h_parms
            )

        # update state based on the node existing
        if desired_state == 'running':
            # ensure_running makes sure it is up and running,
            # making sure it is installed also
            changed, node_stub = ensure_node_running(
                    module=module, hv_conn=hv_conn,
                    node_stub=node_stub, h_parms=h_parms
            )
            if 'tmp_changed' in vars():
                # update changed if we had to build it.
                changed = tmp_changed

        if desired_state == 'stopped':
            # ensure that the node is stopped, this should include
            # making sure it is installed also
            changed, node_stub = ensure_node_stopped(
                    module=module, hv_conn=hv_conn, node_stub=node_stub
            )

        if desired_state == 'present':
            # ensure that the node is installed, we can determine this by
            # making sure it is built (not absent)
            changed, node_stub = ensure_node_present(
                    module=module, hv_conn=hv_conn,
                    node_stub=node_stub, h_parms=h_parms
            )

        if desired_state == 'absent':
            changed, node_stub = ensure_node_absent(
                    module=module, hv_conn=hv_conn, node_stub=node_stub
            )

    # in order to return, we must have a node object and a status (changed) of
    # whether or not state has changed to the desired state
    return {
        'changed': changed,
        'device': _serialize_device(module, node_stub)
    }


def main():
    """Main function, calls ensure_state to handle all the logic
    for determining which ensure_node_<state> function to call.
    mainly to keep this function clean
    """
    module = AnsibleModule(
        argument_spec=dict(
            auth_token=dict(
                default=os.environ.get(HOSTVIRTUAL_API_KEY_ENV_VAR),
                no_log=True),
            hostname=dict(required=True, aliases=['name']),
            mbpkgid=dict(required=True),
            operating_system=dict(required=True),
            ssh_public_key=dict(required=True),
            location=dict(required=True),
            state=dict(choices=ALLOWED_STATES, default='running'),
        ),
    )

    # TODO: make sure this is worth having
    if not module.params.get('auth_token'):
        _fail_msg = ("if HostVirtual API key is not in environment "
                     "variable %s, the auth_token parameter "
                     "is required" % HOSTVIRTUAL_API_KEY_ENV_VAR)
        module.fail_json(msg=_fail_msg)

    auth_token = module.params.get('auth_token')

    hv_driver = get_driver(Provider.HOSTVIRTUAL)
    hv_conn = hv_driver(auth_token)

    # get the desired state, I'm pretty sure
    desired_state = module.params.get('state').lower()

    # pass in a list of locations and oses that are allowed to be used.
    # these can't be in the module instantiation above since they are
    # likely to change at any given time... not optimal
    # available locations
    avail_locs = hv_conn.list_locations()

    # available operating systems
    avail_oses = hv_conn.list_images()

    ##
    # get the passed in parameters
    ##
    h_parms = {}
    # get and check the hostname, raises exception if fails
    h_parms['hostname'] = _get_valid_hostname(module)

    # make sure we get the ssh_key
    h_parms['ssh_key'] = _get_ssh_auth(module)

    # get the image based on the os ID/Name provided
    # the get_os function call will raise an exception if there is a problem
    h_parms['image'] = _get_os(module, avail_oses)

    # get the location based on the location ID/Name provided
    # the get_location function call will raise an exception
    # if there is a problem
    h_parms['location'] = _get_location(module, avail_locs)

    # and lastly, supply the mbpkgid
    h_parms['mbpkgid'] = module.params.get('mbpkgid')

    try:
        # build_provisioned_node returns a dictionary so we just reference
        # the return value here
        module.exit_json(**ensure_state(
                                desired_state=desired_state, module=module,
                                hv_conn=hv_conn, h_parms=h_parms))
    except Exception as e:
        _fail_msg = ("failed to set machine state for node {0}"
                     "to {1}. Error was: {2}"
                     .format(h_parms['hostname'], desired_state, str(e)))
        module.fail_json(msg=_fail_msg)
    ###

    # End Section: Main functions
    #
    ###


if __name__ == '__main__':
    main()
