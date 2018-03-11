#!/usr/bin/python
import time
import os
import re
import json
from libcloud.compute.base import NodeAuthSSHKey
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: hv_build_existing_node

short_description: build an unbuilt but existing node

description:
    - Nodes may exist already so we will see if it's built
    - and build it if it isn't already
    - required is that the node exists already and
    - we have configured the mbpkgid
    - we expect to be able to get the node from libcloud
    - from the mbpkgid
'''

HOSTVIRTUAL_API_KEY_ENV_VAR = "HOSTVIRTUAL_API_KEY"

NAME_RE = '({0}|{0}{1}*{0})'.format('[a-zA-Z0-9]', '[a-zA-Z0-9\-]')
HOSTNAME_RE = '({0}\.)*{0}$'.format(NAME_RE)
MAX_DEVICES = 100

ALLOWED_STATES = ['building', 'pending', 'running', 'stopping',
                  'rebooting', 'starting', 'terminated', 'stopped']

# until the api gets fixed so it's more flexible
API_ROOT = ''


###
#
# Section: Helper functions
#
##
def _get_valid_hostname(hostname):
    """The user will set the hostname so we have to check if it's valid
    hostname:   string of an intended hostname
    Returns:
        Bool
    """
    if re.match(HOSTNAME_RE, hostname) is None:
        raise Exception("Invalid hostname: {}".format(hostname))
    return hostname


def _get_ssh_auth(ssh_key):
    key = open(ssh_key).read()
    auth = NodeAuthSSHKey(pubkey=key)
    return auth.pubkey


def _serialize_device(device):
    """
    Standard represenation for a device as returned by various tasks::

        {
            'id': 'device_id'
            'hostname': 'device_hostname',
            'tags': [],
            'state': 'device_state',
            'ip_addresses': [
                {
                    "address": "147.75.194.227",
                    "address_family": 4,
                    "public": true
                },
                {
                    "address": "2604:1380:2:5200::3",
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
            "public_ipv4": "147.75.194.227",
            "public_ipv6": "2604:1380:2:5200::3",
        }

    """
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


def _get_location(avail_locs, loc_arg):
    """Check if a location is allowed/available

    Raises an exception if we can't use it
    Returns a location object otherwise
    """
    location = None
    loc_possible_list = [loc for loc in avail_locs
                         if os.name == loc_arg or loc.id == loc_arg]

    if not loc_possible_list:
        _msg = "Image '%s' not found" % loc_arg
        raise Exception(_msg)
    else:
        location = loc_possible_list[0]
    return location


def _get_os(avail_oses, os_arg):
    """Check if provided os is allowed/available

    Raises an exception if we can't use it
    Returns an image/OS object otherwise
    """
    image = None
    os_possible_list = [os for os in avail_oses
                        if os.name == os_arg or os.id == os_arg]

    if not os_possible_list:
        _msg = "Image '%s' not found" % os_arg
        raise Exception(_msg)
    else:
        image = os_possible_list[0]
    return image


def _get_node_stub(hv_conn=None, node_id=None):
    """Just try to get the node, otherwise return None"""
    node_stub = None
    try:
        node_stub = hv_conn.ex_get_node(node_id)
    except Exception as e:
        pass
    return node_stub


def _wait_for_state(
            hv_conn=None, node_id=None,
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
        except Exception:
            pass
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
def do_build_new_node(hv_conn, h_parms):
    """Build nodes that have never been built"""
    # set up params to build the node
    params = {
        'mbpkgid': h_parms['mbpkgid'],
        'image': h_parms['image'].id,
        'fqdn': h_parms['hostname'],
        'location': h_parms['location'],
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
        _msg = "Failed to build node for mbpkgid {}".format(h_parms['mbpkgid'])
        raise Exception(_msg)

    # get the new version of the node, hopefully showing
    # using wait_for_build_complete defauilt timeout (10 minutes)
    node = _wait_for_state(
        hv_conn=hv_conn,
        node_id=h_parms['mbpkgid'],
        desired_state='running'
    )
    changed = True
    return changed, node


def do_build_terminated_node(hv_conn, node_stub, h_parms):
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
        _msg = "Failed to build node for mbpkgid {}".format(node_stub.id)
        raise Exception(_msg)

    # get the new version of the node, hopefully showing
    # that it's built and all that

    # get the new version of the node, hopefully showing
    # using wait_for_build_complete defauilt timeout (10 minutes)
    node = _wait_for_state(
        hv_conn=hv_conn,
        node_id=h_parms['mbpkgid'],
        desired_state='running'
    )
    changed = True
    return changed, node


def do_delete_node(
            module=None, hv_conn=None, node_stub=None,
            avail_locs=[], avail_oses=[]
        ):
    """uninstall the node, making sure it's terminated before returning"""


def do_start_node(
            module=None, hv_conn=None, node_stub=None,
            avail_locs=[], avail_oses=[]
        ):
    pass


def do_stop_node(
            module=None, hv_conn=None, node_stub=None,
            avail_locs=[], avail_oses=[]
        ):
    pass


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
# the oddest case would be ensure_terminated (uninstalled) where the node
# has never been built. This would require building, which will create the node
# on disk and then do a terminate call since we don't have a "setup_node"
# type api call that configures the node, get's it's IP, sets up which dom0 it
# should be on and whatnot.
#
###
def ensure_node_running(
            module=None, hv_conn=None, node_stub=None, h_parms=None
        ):
    """Called when we want to just make sure the node is running

    This function calls ensure state == 'running'
    """
    changed = False
    node = node_stub
    if node.state != 'running':
        # do some stuff
        pass
    return changed, node


def ensure_node_stopped(
            module=None, hv_conn=None, node_stub=None, h_parms=None
        ):
    """Called when we want to just make sure that a node is NOT running
    """
    changed = False
    node = node_stub
    if node.state != 'stopped':
        # do some stuff
        pass
    return changed, node


def ensure_node_present(hv_conn=None, node_stub=None, h_parms=None):
    """Called when we want to just make sure that a node is NOT terminated
    """
    # default state
    changed = False
    node = node_stub

    # only do anything if the node.state == 'terminated'
    # default is to leave 'changed' as False and return it and the node.
    if node.state == 'terminated':
        # otherwise,,, build the node.
        changed, node = do_build_terminated_node(hv_conn, node_stub, h_parms)
    return changed, node


def ensure_node_terminated(hv_conn=None, node_stub=None):
    """Ensure the node is not installed, uninstall it if it is installed
    """
    # default return values
    changed = False
    node = node_stub

    # uninstall the node if it is not showing up as terminated.
    if node.state != 'terminated':
        # uninstall the node
        deleted = hv_conn.connection.ex_delete_node(node=node)
        if not deleted:
            _msg = "Seems we had trouble deleting the node"
            raise Exception(_msg)
        else:
            # wait for the node to say it's deleted
            changed = True
            # wait for the node
            node = _wait_for_state(
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
            h_parms={}
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
    node_stub = _get_node_stub(h_parms['mbpkgid'])

    ###
    # DIE if the node has never been built and we are being asked to uninstall
    # we can't uninstall the OS on a node that isn't even in the DB
    ###
    if not node_stub and desired_state == 'terminated':
        raise Exception("Cannot terminate a node that doesn't exist."
                        "Please build first, then you can uninstall it.")

    ###
    # we got here so there must be a node
    ###

    # We only need to do any work if the below conditions exist
    # otherwise we will return the defaults
    if node_stub is None or desired_state != node_stub.state:
        # main block here, no else as we would just return
        # build the node if it doesn't exist
        if node_stub is None:
            # all  states require the node to be installed so do that first.
            tmp_changed, node = ensure_node_present(
                hv_conn=hv_conn, node_stub=node_stub, h_parms=h_parms
            )

        # update state based on the node existing
        if desired_state == 'running':
            # ensure_running makes sure it is up and running,
            # making sure it is installed also
            changed, node = ensure_node_running(
                    hv_conn=hv_conn, node_stub=node_stub, h_parms=h_parms
            )

        if desired_state == 'stopped':
            # ensure that the node is stopped, this should include
            # making sure it is installed also
            changed, node = ensure_node_stopped(
                    hv_conn=hv_conn, node_stub=node_stub, h_parms=h_parms
            )

        if desired_state == 'present':
            # ensure that the node is installed, we can determine this by
            # making sure it is built (not terminated)
            changed, node = ensure_node_present(
                    hv_conn=hv_conn, node_stub=node_stub, h_parms=h_parms
            )

        if desired_state == 'terminated':
            changed, node = ensure_node_terminated(
                    hv_conn=hv_conn, node_stub=node_stub
            )

    # in order to return, we must have a node object and a status (changed) of
    # whether or not state has changed to the desired state
    return {
        'changed': changed,
        'device': _serialize_device(node)
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
    h_parms['hostname'] = _get_valid_hostname(module.params.get('hostname'))

    # make sure we get the ssh_key
    h_parms['ssh_key'] = _get_ssh_auth(module.params.get('ssh_public_key'))

    # get the image based on the os ID/Name provided
    # the get_os function call will raise an exception if there is a problem
    h_parms['image'] = _get_os(
        avail_oses,
        module.params.get('operating_system')
    )

    # get the location based on the location ID/Name provided
    # the get_location function call will raise an exception
    # if there is a problem
    h_parms['location'] = _get_location(
        avail_locs,
        module.params.get('operating_system')
    )

    # and lastly, supply the mbpkgid
    h_parms['mbpkgid'] = module.params.get('mbpkgid')

    try:
        # build_provisioned_node returns a dictionary so we just reference
        # the return value here
        module.exit_json(**ensure_state(
                                desired_state=desired_state, module=module,
                                hv_conn=hv_conn, h_parms=h_parms))
    except Exception as e:
        _fail_msg = ('failed to set machine state '
                     '%s, error: %s' % (desired_state, str(e)))
        module.fail_json(msg=_fail_msg)
    ###
    #
    # End Section: Main functions
    #
    ###


if __name__ == '__main__':
    main()
