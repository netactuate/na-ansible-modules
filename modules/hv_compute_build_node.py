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

ALLOWED_STATES = ['absent', 'active', 'inactive', 'rebooted',
                  'present', 'running']
HOSTVIRTUAL_STATES = ['building', 'pending', 'running', 'stopping',
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


def get_image_by_os(hv_conn, operating_system):
    image = None
    images = hv_conn.list_images()
    for i in images:
        if i.name == operating_system:
            image = i
    if image is None:
        _msg = "Image '%s' not found" % operating_system
        raise Exception(_msg)
    return image


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


def build_node(state, module, hv_conn):
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

    # get the image based on the os provided
    image = get_image_by_os(hv_conn, module.params.get('operating_system'))

    # we should be able to get the Node from the mbpkgid
    node_stub = hv_conn.ex_get_node(module.params.get('mbpkgid'))

    # default to not changed
    changed = False

    # only build if it's still 'terminated'
    if node_stub.state == 'terminated':

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

    return {
        'changed': changed,
        'device': serialize_device(node)
    }


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

    state = module.params.get('state')

    try:
        # build_provisioned_node returns a dictionary so we just reference
        # the return value here
        module.exit_json(**build_node(state, module, hv_conn))
    except Exception as e:
        _fail_msg = ('failed to set machine state '
                     '%s, error: %s' % (state, str(e)))
        module.fail_json(msg=_fail_msg)


if __name__ == '__main__':
    main()
