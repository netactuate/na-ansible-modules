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


def get_valid_hostname(hostname):
    """The user will set the hostname so we have to check if it's valid
    hostname:   string of an intended hostname
    Returns:
        Bool
    """
    if re.match(HOSTNAME_RE, hostname) is None:
        raise Exception("Invalid hostname: {}".format(hostname))
    return hostname


def wait_for_build_complete(hv_conn, node_id, timeout=600, interval=10.0):
    try_node = None
    for i in range(0, timeout, int(interval)):
        try:
            try_node = hv_conn.ex_get_node(node_id)
            if try_node.state == 'running':
                break
        except Exception:
            pass
        time.sleep(interval)
    return try_node


def get_ssh_auth(ssh_key):
    key = open(ssh_key).read()
    auth = NodeAuthSSHKey(pubkey=key)
    return auth.pubkey


def serialize_device(device):
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


def get_location(avail_locs, loc_arg):
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


def get_os(avail_oses, os_arg):
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


def build_terminated(hv_conn, node_stub, image, hostname, ssh_key):
    """Build nodes that have been uninstalled


    """
    # TODO: We need to check if there is a location associated with the node
    # otherwise we need to set the location based on passed in params.

    # set up params to build the node
    params = {
        'mbpkgid': node_stub.id,
        'image': image.id,
        'fqdn': hostname,
        'location': node_stub.extra['location'],
        'ssh_key': ssh_key
    }

    # do it using the api
    try:
        hv_conn.connection.request(API_ROOT + '/cloud/server/build',
                                   data=json.dumps(params),
                                   method='POST').object
    except Exception:
        _msg = "Failed to build node for mbpkgid {}".format(node_stub.id)
        raise Exception(_msg)
        # get the new version of the node, hopefully showing
        # that it's built and all that
        node = wait_for_build_complete(hv_conn, node_stub.id)

        if node.state != 'terminated':
            changed = True
        else:
            node = node_stub
    return node, changed


def work_on_node(desired_state='running', module=None, hv_conn=None,
                 avail_locs=[], avail_oses=[]):
    """Main function call that will check desired state
    and call the appropriate function.

    The called functions will check node state and alter
    their state as needed.

    Here for a NOTE so I don't have to keep scrolling to the top
    ALLOWED_STATES = ['building', 'pending', 'running', 'stopping',
                      'rebooting', 'starting', 'terminated', 'stopped']
    possible desired states = ['running', 'stopped', 'terminated', 'present']
    Note that 'present' equates to !terminated
    """
    # TRY to get the node from the mbpkgid provided (required)
    # Everything else we call MUST account for node_stub being None
    # node_stub being None indicates it has never been built.
    try:
        node_stub = hv_conn.ex_get_node(module.params.get('mbpkgid'))
    except Exception as e:
        # node doesn't exist, must create it and then make sure it's running
        node_stub = None

    # update state based on the node not existing in the DB yet
    if node_stub is None:
        if desired_state == 'running':
            # ensure_running makes sure it is up and running,
            # making sure it is installed also
            ensure_running(module=module, hv_conn=hv_conn, node_stub=node_stub,
                           avail_locs=avail_locs, avail_oses=avail_oses)

        if desired_state == 'stopped':
            # ensure that the node is stopped, this should include
            # making sure it is installed also
            ensure_stopped(module=module, hv_conn=hv_conn, node_stub=node_stub,
                           avail_locs=avail_locs, avail_oses=avail_oses)

        if desired_state == 'present':
            # ensure that the node is installed, we can determine this by
            # making sure it is built (not terminated)
            ensure_present(module=module, hv_conn=hv_conn, node_stub=node_stub,
                           avail_locs=avail_locs, avail_oses=avail_oses)

    # update state based on the node existing
    else:
        if desired_state == 'running':
            build_node(desired_state, module, hv_conn, node_stub,
                       avail_oses, avail_locs)


def ensure_running(module=None, hv_conn=None, node_stub=None,
                   avail_locs=[], avail_oses=[]):
    """Called when we want to just make sure the node is running

    This function calls ensure_
    """
    pass


def ensure_stopped(module=None, hv_conn=None, node_stub=None,
                   avail_locs=[], avail_oses=[]):
    """Called when we want to just make sure that a node is NOT running
    """
    pass


def ensure_present(module=None, hv_conn=None, node_stub=None,
                   avail_locs=[], avail_oses=[]):
    """Called when we want to just make sure that a node is NOT terminated
    """
    pass



def build_node(state, module, avail_oses, avail_locs, hv_conn):
    """Build a node, if it's not currently in a built state
    """
    for param in ('hostname', 'operating_system', 'mbpkgid', 'ssh_public_key'):
        if not module.params.get(param):
            raise Exception("%s parameter is required for building "
                            "device." % param)

    # get and check the hostname, raises exception if fails
    hostname = get_valid_hostname(module.params.get('hostname'))

    # make sure we get the ssh_key
    ssh_key = get_ssh_auth(module.params.get('ssh_public_key'))

    # get the image based on the os ID/Name provided
    image = get_os(avail_oses, module.params.get('operating_system'))

    # get the location based on the location ID/Name provided
    location = get_location(avail_locs, module.params.get('operating_system'))


    # default to not changed
    changed = False

    # do stuff if terminated
    if node_stub.state == 'terminated':
        node, changed = build_terminated(node_stub, image, hostname, ssh_key)

    return {
        'changed': changed,
        'device': serialize_device(node)
    }


def main():
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
    state = module.params.get('state')

    # pass in a list of locations and oses that are allowed to be used.
    # these can't be in the module instantiation above since they are
    # likely to change at any given time... not optimal
    # available locations
    avail_locs = hv_conn.list_locations()

    # available operating systems
    avail_oses = hv_conn.list_images()

    try:
        # build_provisioned_node returns a dictionary so we just reference
        # the return value here
        module.exit_json(**work_on_node(
                                desired_state=state, module=module,
                                hv_conn=hv_conn, avail_locs=avail_locs,
                                avail_oses=avail_oses))
    except Exception as e:
        _fail_msg = ('failed to set machine state '
                     '%s, error: %s' % (state, str(e)))
        module.fail_json(msg=_fail_msg)


if __name__ == '__main__':
    main()
