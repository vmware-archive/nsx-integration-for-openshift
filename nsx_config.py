#!/usr/bin/python
'''
Created on Jun 8, 2017
@author: yfan, skai
'''

import argparse
import atexit
import json
import logging
import sys
import time
from urllib import urlencode
from vmware_nsxlib import v3  # noqa
from vmware_nsxlib.v3 import config  # noqa

from com.vmware import cis_client
from com.vmware.vcenter.vm import hardware_client
from com.vmware import vcenter_client
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from vmware.vapi.lib.connect import get_requests_connector
from vmware.vapi.security.session import create_session_security_context
from vmware.vapi.security.user_password import \
    create_user_password_security_context
from vmware.vapi.stdlib.client.factories import StubConfigurationFactory


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

NCP_CLUSTER_KEY = "ncp/cluster"
NCP_EXTERNAL_KEY = "ncp/external"
NCP_NODE_KEY = "ncp/node_name"


class TinyClient(object):
    """
    A python version tiny client for NSX Transformer.
    For single thread use only, no sync inside.
    """
    DEFAULT_VERSION = 'v1'

    def __init__(self, args):
        nsxlib_config = config.NsxLibConfig(
            username=args.mp_user,
            password=args.mp_password,
            nsx_api_managers=args.mp_ip.split(','),
            ca_file=args.mp_cert_file)
        self.nsxlib = v3.NsxLib(nsxlib_config)
        self.content_type = "application/json"
        self.headers = {'content-type': self.content_type}

    def _request(self, method, endpoint, payload="", url_parameters=None):
        """
        The only interface to send request to NSX Manager. All other calls
        will call through this method.
        @param method:   the http method, GET/POST/UPDATE/DELETE
        @param endpoint: the url of http call
        @param payload:  the request body of http call
        @param url_parameters: the url parameter, a dict format
        """
        url_params_string = ""
        if url_parameters:
            if "?" in endpoint:
                url_params_string = "&%s" % urlencode(url_parameters)
            else:
                url_params_string = "?%s" % urlencode(url_parameters)
        request = "%s%s" % (endpoint, url_params_string)
        logger.info('request: %s', request)
        return self.nsxlib.client._rest_call(request, method, payload,
                                             self.headers)

    def request(self, method, endpoint, payload="", params=None):
        """
        The user interface to the method _request. All user calls
        will call through this method.
        @param method:   the http method, GET/POST/UPDATE/DELETE
        @param endpoint: the url of http call
        @param payload:  the request body of http call
        @param params: short for the url parameter, a dict format
        """
        if not isinstance(payload, str):
            payload = json.dumps(payload)
        logger.info('method: %s, endpoint: %s, payload: %s, params: %s',
                    method, endpoint, payload, params)
        return self._request(method, endpoint, payload,
                             url_parameters=params)

    def create(self, url, py_dict, params=None):
        """
        The create method.
        @param py_dict:  the request body of http call, dict format
        @param params:   short for the url parameter, dict format
        """
        return self.request('POST', url, payload=py_dict,
                            params=params)

    def read(self, url, object_id=None, params=None):
        """
        The read method.
        @param py_dict:  the request body of http call, dict format
        @param params:   short for the url parameter, dict format
        """
        if object_id:
            return self.request('GET', "%s/%s" % (url, object_id),
                                params=params)
        return self.request('GET', url, params=params)

    def search(self, search_params):
        """
        This exposes the search API.
        :param search_params: a dictionary to specify the filters
        """
        search_url = 'search'
        param_list = []
        for key, value in search_params.items():
            param_list.append('%s:%s' % (key, value))
        return self.request('GET', search_url, params={
            'query': ' AND '.join(param_list)})

    def update(self, url, object_id, py_dict, params=None):
        """
        The update method.
        @param py_dict:  the request body of http call, dict format
        @param params:   short for the url parameter, dict format
        """
        return self.request('PUT', "%s/%s" % (url, object_id),
                            py_dict, params=params)

    def delete(self, url, object_id, params=None):
        """
        The delete method.
        @param py_dict:  the request body of http call, dict format
        @param params:   short for the url parameter, dict format
        """
        return self.request("DELETE", "%s/%s" % (url, object_id),
                            params=params)

    def get_all(self, params=None):
        """
        The wrapper method of read to get all objects.
        """
        res = self.read(params=params)
        if res:
            return res['results']
        return []


def getargs():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mp',
                        dest="mp_ip",
                        default="",
                        help='IP of NSX manager')
    parser.add_argument('--cert',
                        dest="mp_cert_file",
                        default="",
                        help='Optional. The file that contains client '
                             'certificate and private key for '
                             'authentication. Defaults to empty str.')
    parser.add_argument('--user',
                        dest="mp_user",
                        default="admin",
                        help='Optional. The MP User. Default: admin')
    parser.add_argument('--password',
                        dest="mp_password",
                        default="Admin!23Admin",
                        help='Optional. The MP password. Default: '
                             'Admin!23Admin')
    parser.add_argument('--k8scluster',
                        dest="k8scluster",
                        default="",
                        help='The k8s/OpenShift cluster name for whole '
                             'configuration Default: k8scluster')
    parser.add_argument('--edge_cluster',
                        dest="edge_cluster",
                        default="",
                        help='Name of the edge cluster for transport zone.')
    parser.add_argument('--tz',
                        dest="tz",
                        default="",
                        help='Name of the transport zone to be created and '
                             'tagged. ')
    parser.add_argument('--t0',
                        dest="t0",
                        default="",
                        help='Name of the tier-0 logical router to be created '
                             'and tagged.')

    parser.add_argument('--pod_ipblock_name',
                        dest="pod_ipblock_name",
                        default="",
                        help='name of IpBlock for pod traffic')
    parser.add_argument('--pod_ipblock_cidr',
                        dest="pod_ipblock_cidr",
                        default='',
                        help='CIDR of IpBlock for pod traffic')

    parser.add_argument('--snat_ippool_name',
                        dest="snat_ippool_name",
                        default='',
                        help='name of IpPool for SNAT')
    parser.add_argument('--snat_ippool_cidr',
                        dest="snat_ippool_cidr",
                        default="",
                        help='CIDR of IpPool for SNAT')

    parser.add_argument('--start_range',
                        dest="start_range",
                        default="",
                        help='Start ip of IpPool for SNAT')

    parser.add_argument('--end_range',
                        dest="end_range",
                        default="",
                        help='End ip of IpPool for SNAT')

    parser.add_argument('--node',
                        dest="node_list",
                        default="",
                        help='Optional. The kubernetes nodes names which are '
                             'corresponding with vm names, split by "," with '
                             'no spaces. Format: node1,node2,'
                             'node3.')

    parser.add_argument('--node_ls',
                        dest="node_ls",
                        default="",
                        help='Name of node logical switch')

    parser.add_argument('--node_lr',
                        dest="node_lr",
                        default="",
                        help='Name of node t1 logical router')

    parser.add_argument('--node_network_cidr',
                        dest="node_network_cidr",
                        default="",
                        help='Subnet to node ls, IP address/mask, '
                             'ex: 172.20.2.0/16')

    parser.add_argument('--vc_host',
                        dest='vc_host',
                        default='',
                        help='IP address of VC')

    parser.add_argument('--vc_user',
                        dest='vc_user',
                        default='',
                        help='User name of VC')

    parser.add_argument('--vc_password',
                        dest='vc_password',
                        default='',
                        help='Password of VC')

    parser.add_argument('--vms',
                        dest='vms',
                        default='',
                        help='Name of the vms, separated by comma')

    parser.add_argument('--skip_verfication',
                        dest='skip_verfication',
                        default=True,
                        help='If using VC cert, set false')

    parser.add_argument('--cert_path',
                        dest='cert_path',
                        default='',
                        help='Absolute path to VC cert')
    args = parser.parse_args()
    return args


def add_tag(py_dict, tag_dict):
    """
    Helper function to add tags to the NSX object body.
    @param py_dict: the NSX object body as dict format
    @param tag_dict: tags to add. dict format.
                     e.g. {"ncp/cluster": "k8scluster"}
    """
    # Check exsiting tags
    existing_tags = []
    if "tags" in py_dict:
        for item in py_dict["tags"]:
            existing_tags.append((item.get("scope"), item.get("tag")))
    else:
        py_dict["tags"] = []
    for (key, value) in tag_dict.items():
        tag = {"scope": key, "tag": value}
        # If the tag already exists, skip it.
        if tag in existing_tags:
            pass
        else:
            py_dict["tags"].append(tag)
    return py_dict


class VMNetworkManager(object):
    def __init__(self, args):
        self.host = args.vc_host
        self.user = args.vc_user
        self.pwd = args.vc_password
        self.skip_verfication = args.skip_verfication
        self.cert_path = args.cert_path
        self.vms = args.vms
        self.node_ls_name = args.node_ls
        self.node_list = args.node_list

    def get_jsonrpc_endpoint_url(self, host):
        # The URL for the stub requests are made against the /api HTTP
        # endpoint of the vCenter system.
        return "https://{}/api".format(host)

    def connect(self, host, user, pwd,
                skip_verification=False,
                cert_path=None,
                suppress_warning=True):
        """
        Create an authenticated stub configuration object that can be used
        to issue requests against vCenter.

        Returns a stub_config that stores the session identifier that can be
        used to issue authenticated requests against vCenter.
        """
        host_url = self.get_jsonrpc_endpoint_url(host)

        session = requests.Session()
        if skip_verification:
            session = self.create_unverified_session(session, suppress_warning)
        elif cert_path:
            session.verify = cert_path
        connector = get_requests_connector(session=session, url=host_url)
        stub_config = StubConfigurationFactory.new_std_configuration(connector)

        return self.login(stub_config, user, pwd)

    def login(self, stub_config, user, pwd):
        """
        Create an authenticated session with vCenter.
        Returns a stub_config that stores the session identifier that can
        be used to issue authenticated requests against vCenter.
        """
        # Pass user credentials (user/password) in the security context to
        # authenticate.
        security_context = create_user_password_security_context(user, pwd)
        stub_config.connector.set_security_context(security_context)

        # Create the stub for the session service
        # and login by creating a session.
        session_svc = cis_client.Session(stub_config)
        session_id = session_svc.create()

        # Store the session identifier in the security
        # context of the stub and use that for all subsequent remote requests
        session_security_context = create_session_security_context(session_id)
        stub_config.connector.set_security_context(session_security_context)

        return stub_config

    def logout(self, stub_config):
        """
        Delete session with vCenter.
        """
        if stub_config:
            session_svc = cis_client.Session(stub_config)
            session_svc.delete()

    def create_unverified_session(self, session, suppress_warning=True):
        """
        Create a unverified session to disable the certificate verification.
        """
        session.verify = False
        if suppress_warning:
            # Suppress unverified https request warnings
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        return session

    def get_vm(self, stub_config, vm_name):
        """
        Return the identifier of a vm
        """
        vm_svc = vcenter_client.VM(stub_config)
        names = set([vm_name])
        vms = vm_svc.list(vcenter_client.VM.FilterSpec(names=names))

        if len(vms) == 0:
            logger.info("VM with name ({}) not found".format(vm_name))
            return None

        vm = vms[0].vm
        logger.info("Found VM '{}' ({})".format(vm_name, vm))
        return vm

    def configure_vnic(self):
        # if user did not set vc host or user or password, do nothing
        if not self.host or not self.user or not self.pwd:
            return
        stub_config = self.connect(self.host, self.user,
                                   self.pwd, self.skip_verfication)
        atexit.register(self.logout, stub_config)
        vm_list = self.vms.split(',')
        node_list = self.node_list.split(',')
        for vm_name, node_name in zip(vm_list, node_list):
            vm = self.get_vm(stub_config, vm_name)
            if not vm:
                raise Exception('Existing vm with name ({}) is required. '
                                'Please create the vm first.'.format(vm_name))

            # After node_ls is created, get the network with the same name
            network_svc = vcenter_client.Network(stub_config)
            filter = vcenter_client.Network.FilterSpec(
                names=set([self.node_ls_name]))
            network_summaries = network_svc.list(filter=filter)
            logger.info(network_summaries)
            if not network_summaries:
                raise Exception('Network with name %s not found on VC %s' %
                                (self.node_ls_name, self.host))

            network = network_summaries[0].network
            ethernet_svc = hardware_client.Ethernet(stub_config)
            logger.info('\n# List all Ethernet adapters for VM %s' % vm_name)
            nic_summaries = ethernet_svc.list(vm=vm)
            logger.info('vm.hardware.Ethernet.list({}) -> {}'
                        .format(vm, nic_summaries))

            # Get information for each Ethernet on the VM
            idle_nic = None
            finished_configuring_current_vm = False
            for nic_summary in nic_summaries:
                nic = nic_summary.nic
                nic_info = ethernet_svc.get(vm=vm, nic=nic)
                logger.info('vm.hardware.Ethernet.get({}, {}) -> {}'.
                            format(vm, nic, nic_info))
                if (nic_info.state == 'CONNECTED' and
                    nic_info.backing.network == network):
                    logger.info("Nic for the network has been configured. "
                                "Finished configuring current VM.")
                    finished_configuring_current_vm = True
                    break
                if nic_info.state == 'NOT_CONNECTED':
                    idle_nic = nic
            if finished_configuring_current_vm:
                continue

            network_type = hardware_client.Ethernet.BackingType.OPAQUE_NETWORK
            if not idle_nic:
                logger.info("No available vnic found, creating new vnic.")
                nic_create_spec = hardware_client.Ethernet.CreateSpec(
                    start_connected=True,
                    allow_guest_control=True,
                    wake_on_lan_enabled=True,
                    backing=hardware_client.Ethernet.BackingSpec(
                        type=network_type,
                        network=network))
                idle_nic = ethernet_svc.create(vm, nic_create_spec)
                logger.info("Created new vnic {}.".format(idle_nic))

            else:
                logger.info("Idle vnic {} found, updating it's network."
                            .format(idle_nic))
                nic_update_spec = hardware_client.Ethernet.UpdateSpec(
                    backing=hardware_client.Ethernet.BackingSpec(
                        type=network_type,
                        network=network),
                    start_connected=True
                )
                ethernet_svc.update(vm, idle_nic, nic_update_spec)
                logger.info("Updated vnic {} with network {}."
                            .format(idle_nic, network))
            idle_nic_info = ethernet_svc.get(vm=vm, nic=idle_nic)
            if idle_nic_info.state == 'NOT_CONNECTED':
                logger.info("Connecting vnic {} with vm {}"
                            .format(idle_nic, vm_name))
                ethernet_svc.connect(vm, idle_nic)


class NSXResourceManager(object):
    def __init__(self, api_client):
        self.api_client = api_client

        self.resource_to_url = {
            'TransportZone': 'transport-zones',
            'LogicalRouter': 'logical-routers',
            'IpBlock': 'pools/ip-blocks',
            'IpPool': 'pools/ip-pools',
            'LogicalSwitch': 'logical-switches',
            'LogicalPort': 'logical-ports',
            'LogicalRouterPort': 'logical-router-ports',
            'VIF': 'fabric/vifs',
            'VM': 'fabric/virtual-machines'
        }

        self.secondary_resource_to_url = {
            'Routing_Advertisement': '/routing/advertisement',
            'Routing_Redistribution': '/routing/redistribution'
        }

    def get_resource_by_type_and_name(self, resource_type, resource_name,
                                      use_search_api=True):
        search_params = {
            'resource_type': resource_type,
            'display_name': resource_name,
        }
        if use_search_api:
            response = self.api_client.search(search_params)
            result_count = response.get('result_count', 0)
            if result_count > 1:
                raise Exception('More than one resource found for type %s and '
                                'name %s', resource_type, resource_name)
            return response['results'][0] if result_count else None
        else:
            result = self.get_all(resource_type)
            resources = []
            for r in result:
                if search_params and all(r.get(k) == v
                                         for k, v in search_params.items()):
                    resources.append(r)
            if len(resources) > 1:
                raise Exception('More than one resource found for type %s and '
                                'name %s', resource_type, resource_name)
            return resources[0] if resources else None

    def get_or_create_resource(self, resource_type, resource_name,
                               params=None, use_search_api=True):
        resource = self.get_resource_by_type_and_name(
            resource_type, resource_name,
            use_search_api=use_search_api)
        if not resource:
            logger.info('Resource of type %s, and name %s not found, creating',
                        resource_type, resource_name)
            # create resource, and return it
            resource_dict = {'display_name': resource_name}
            if params:
                resource_dict.update(params)
            resource = self.api_client.create(
                self.resource_to_url[resource_type], resource_dict)
        logger.debug('obtained resource: %s', resource)
        return resource

    def get_all(self, resource_type, params=None):
        """
        The wrapper method of read to get all objects.
        """
        res = self.api_client.read(
            self.resource_to_url[resource_type], params=params)
        if res:
            return res['results']
        return []

    def get_mac_table_for_lp(self, lp_id):
        url = '/logical-ports/%s/mac-table?source=realtime' % lp_id
        response = self.api_client.read(url)
        return response['results']

    def update_resource(self, resource):
        url = self.resource_to_url[resource['resource_type']]
        self.api_client.update(url, resource['id'], resource)

    def update_secondary_resource(self, resource_type, resource_id,
                                  secondary_resource_type,
                                  secondary_resource):
        url = (self.resource_to_url[resource_type] + '/' + resource_id + '/' +
               self.secondary_resource_to_url[secondary_resource_type])
        self.api_client.update(url, "", secondary_resource)

    def get_secondary_resource(self, resource_type, resource_id,
                               secondary_resource_type):
        url = (self.resource_to_url[resource_type] + '/' + resource_id + '/' +
               self.secondary_resource_to_url[secondary_resource_type])
        return self.api_client.read(url)


class ConfigurationManager(object):
    def __init__(self, args, api_client):
        self.resource_manager = NSXResourceManager(api_client)
        self.vm_network_manager = VMNetworkManager(args)

        self.manager_ip = args.mp_ip
        self.username = args.mp_user
        self.password = args.mp_password

        self.cluster_name = args.k8scluster
        self.transport_zone_name = args.tz

        self.t0_router_name = args.t0
        self.edge_cluster_name = args.edge_cluster

        self.pod_ipblock_name = args.pod_ipblock_name
        self.pod_ipblock_cidr = args.pod_ipblock_cidr
        self.snat_ippool_name = args.snat_ippool_name
        self.snat_ippool_cidr = args.snat_ippool_cidr
        self.start_range = args.start_range
        self.end_range = args.end_range

        self.mac_to_node_name = {}
        self.node_ls_name = args.node_ls
        self.node_lr_name = args.node_lr
        self.node_network_cidr = args.node_network_cidr
        self.vm_list = args.vms.split(',')
        self.node_list = args.node_list.split(',')

    def _has_tags(self, resource, required_tags):
        if not required_tags:
            raise Exception('The required tags dictionary is empty')
        if 'tags' not in resource:
            return False

        current_tags = resource['tags']
        current_keys = set(tag['scope'] for tag in current_tags)
        for required_tag_key, required_tag_value in required_tags.items():
            if required_tag_key not in current_keys:
                return False

            required_tag = {
                'scope': required_tag_key,
                'tag': required_tag_value,
            }
            if required_tag not in current_tags:
                logger.warning('One of existing tags has the same key with '
                               'the required tag %s. Existing tags: %s',
                               required_tag, current_tags)
        return True

    def _handle_general_configuration(self, resource_type, resource_name,
                                      params=None, required_tags=None,
                                      use_search_api=True):
        """
        The algorithm for 'general configuration' is: Check if the resource
        with specified type and name exists and only one exists.
        Raise an exception if more than one resources found.
        If not found, create one.
        Then continue and tag the resource if it doesn't yet have all of the
        required tags.
        Some resource (like Transport Zone), the payload from search API is
        not usable by nsx api, we will just use the nsx client api for it
        """

        resource = self.resource_manager.get_or_create_resource(
            resource_type, resource_name, params,
            use_search_api=use_search_api)
        return resource

    def handle_transport_zone(self):
        params = {
            'host_switch_name': 'nsxvswitch',
            'transport_type': 'OVERLAY',
        }
        required_tags = {NCP_CLUSTER_KEY: self.cluster_name}
        overlay_tz = self._handle_general_configuration(
            'TransportZone', self.transport_zone_name, params, required_tags,
            use_search_api=False)
        sys.stdout.write("overlay_tz: %s " % overlay_tz['id'])

    def handle_t0_router(self):
        edge_cluster = self.resource_manager.get_resource_by_type_and_name(
            'EdgeCluster', self.edge_cluster_name)
        if not edge_cluster:
            logger.critical('No edge cluster with name %s found. '
                            'Configuration of T0 router is aborted.',
                            self.edge_cluster_name)
            return

        params = {
            'router_type': 'TIER0',
            'edge_cluster_id': edge_cluster['id'],
            'high_availability_mode': 'ACTIVE_STANDBY',
        }
        required_tags = {NCP_CLUSTER_KEY: self.cluster_name}
        self._handle_general_configuration(
            'LogicalRouter', self.t0_router_name, params, required_tags,
            use_search_api=False)
        t0 = self.resource_manager.get_resource_by_type_and_name(
            'LogicalRouter', self.t0_router_name, use_search_api=False)
        redistribution = self.resource_manager.get_secondary_resource(
            'LogicalRouter', t0['id'], 'Routing_Redistribution')
        redistribution['bgp_enabled'] = True
        self.resource_manager.update_secondary_resource(
            'LogicalRouter', t0['id'],
            'Routing_Redistribution', redistribution)
        sys.stdout.write("t0_router: %s " % t0['id'])

    def _handle_ipblock(self, ipblock_name, ipblock_cidr, required_tags):
        # handle ipblock configuration for a specific block name
        params = {'cidr': ipblock_cidr}
        ipblock = self._handle_general_configuration(
            'IpBlock', ipblock_name, params, required_tags)
        sys.stdout.write("container_ip_block: %s " % ipblock['id'])

    def _handle_ippool(self, ippool_name, ippool_cidr,
                       start_range, end_range, required_tags):
        # handle ipblock configuration for a specific block name
        params = {"subnets": [
            {
                "allocation_ranges": [
                    {
                        "start": start_range,
                        "end": end_range
                    }
                ],
                "cidr": ippool_cidr}]
        }
        ippool = self._handle_general_configuration(
            'IpPool', ippool_name, params, required_tags)
        sys.stdout.write("external_ip_pool: %s " % ippool['id'])

    def handle_ipblocks(self):
        # IP block for pod traffic
        self._handle_ipblock(self.pod_ipblock_name, self.pod_ipblock_cidr, {
            NCP_CLUSTER_KEY: self.cluster_name})

        # IP block for SNAT
        self._handle_ippool(self.snat_ippool_name, self.snat_ippool_cidr,
                            self.start_range, self.end_range,
                            {NCP_EXTERNAL_KEY: 'true',
                             NCP_CLUSTER_KEY: self.cluster_name})

    def handle_t1_router(self):
        # Get node_lr. Create it if not present
        # After creation, connect it to T0 and node-ls
        node_lr_name = self.node_lr_name
        node_lr = self.resource_manager.get_resource_by_type_and_name(
            'LogicalRouter', node_lr_name)
        # we first check if node_lr has been configured or not
        if not node_lr:
            t0_router = self.resource_manager.get_resource_by_type_and_name(
                'LogicalRouter', self.t0_router_name)
            if not t0_router:
                logger.critical('No T0 router with name %s found. '
                                'Configuration of T1 %s router is aborted.' %
                                (self.t0_router_name, node_lr_name))
                return

            params = {
                'router_type': 'TIER1',
                'high_availability_mode': 'ACTIVE_STANDBY',
            }
            node_lr = self.resource_manager.get_or_create_resource(
                'LogicalRouter', self.node_lr_name, params)

            # Then we add router link port on t0 and t1
            t1_id = node_lr['id']
            t0_id = t0_router['id']
            t0_router_port_name = "Link_to_%s" % node_lr_name
            params1 = {
                'display_name': t0_router_port_name,
                'resource_type': 'LogicalRouterLinkPortOnTIER0',
                'logical_router_id': t0_id,
                'tags': []
            }
            t0_router_port = self.resource_manager.get_or_create_resource(
                'LogicalRouterPort', t0_router_port_name, params1)
            t1_router_port_name = "Link_to_%s" % t0_router['display_name']
            params2 = {
                'display_name': t1_router_port_name,
                'resource_type': 'LogicalRouterLinkPortOnTIER1',
                'logical_router_id': t1_id,
                'tags': [],
                'linked_logical_router_port_id': {
                    'target_id': t0_router_port['id']}
            }
            self.resource_manager.get_or_create_resource(
                'LogicalRouterPort', t1_router_port_name, params2)

            t1_router_switch_port_name = "Link_to_%s" % self.node_ls_name
            node_ls_port = self.resource_manager.get_resource_by_type_and_name(
                'LogicalPort', 'To_%s' % self.node_lr_name)
            ip = self.node_network_cidr.split('/')[0]
            cidr_len = self.node_network_cidr.split('/')[1]
            params3 = {
                'display_name': t1_router_switch_port_name,
                'resource_type': 'LogicalRouterDownLinkPort',
                'logical_router_id': t1_id,
                'tags': [],
                'linked_logical_switch_port_id': {
                    'target_id': node_ls_port['id']},
                'subnets': [{
                    'ip_addresses': [ip],
                    'prefix_length': cidr_len
                }]
            }
            self.resource_manager.get_or_create_resource(
                'LogicalRouterPort', t1_router_switch_port_name, params3)

        # Finally we enale node_lr for route advertisement
        advertisement = self.resource_manager.get_secondary_resource(
            'LogicalRouter', node_lr['id'], 'Routing_Advertisement')
        advertisement['enabled'] = True
        advertisement['advertise_nsx_connected_routes'] = True
        advertisement['advertise_lb_vip'] = True
        advertisement['advertise_static_routes'] = True
        advertisement['advertise_nat_routes'] = True
        advertisement['advertise_lb_snat_ip'] = True
        self.resource_manager.update_secondary_resource(
            'LogicalRouter', node_lr['id'],
            'Routing_Advertisement', advertisement)

    def handle_vif(self):
        # get node-ls. Create it if it doesn't exist yet
        transport_zone = self.resource_manager.get_resource_by_type_and_name(
            'TransportZone', self.transport_zone_name)

        params_1 = {
            'transport_zone_id': transport_zone['id'],
            'admin_state': 'UP',
            'replication_mode': 'MTEP',
        }
        node_ls = self.resource_manager.get_or_create_resource(
            'LogicalSwitch', self.node_ls_name, params_1)

        # create logical ports to node_lr
        logical_port_to_node_ls = 'To_%s' % self.node_lr_name
        params_2 = {
            'logical_switch_id': node_ls['id'],
            'display_name': logical_port_to_node_ls,
            'admin_state': 'UP',
            'attachment': None,
            'tags': [],
            'address_bindings': None
        }
        self.resource_manager.get_or_create_resource(
            'LogicalPort', logical_port_to_node_ls, params_2)

        logger.info('node_ls: %s', node_ls)

        # After node ls is created, configure vnic if user provided
        # Sleep 20 seconds for vc to discover node ls
        time.sleep(20)
        self.vm_network_manager.configure_vnic()
        # Sleep 10 senconds for nsx to discover vif connected to node_ls
        time.sleep(10)
        vms_id = {}
        id_port = {}
        for vm_name in self.vm_list:
            params = {"display_name": vm_name}
            vm_info = self.resource_manager.get_all('VM', params=params)
            if not vm_info:
                logger.warning("Cannot find the VM %s" % vm_name)
            else:
                vms_id[vm_name] = vm_info[0]['external_id']

        for vmid in vms_id.values():
            if not vmid:
                continue
            params = {"owner_vm_id": vmid}
            vm_infos = self.resource_manager.get_all('VIF', params=params)
            for vm_info in vm_infos:
                if 'lport_attachment_id' in vm_info:
                    # In KVM, the vm managerment also has
                    # lport_attachement_id, but there is no lsp for it.
                    att_id = vm_info["lport_attachment_id"]
                    lsp_info = self.resource_manager.get_all(
                        'LogicalPort', params={"attachment_id": att_id})
                    for lsp in lsp_info:
                        if lsp['logical_switch_id'] == node_ls['id']:
                            id_port[vmid] = lsp
                            break

        for (vm_name, node_name) in zip(self.vm_list, self.node_list):
            lsp = id_port.get(vms_id[vm_name])
            if not lsp:
                logger.warning("Cannot find any VIF on the VM %s" % vm_name)
            else:
                required_tags = {
                    NCP_CLUSTER_KEY: self.cluster_name,
                    NCP_NODE_KEY: node_name
                }
                logger.info('required tags: %s, port: %s', required_tags, lsp)
                if not self._has_tags(lsp, required_tags):
                    lsp = add_tag(lsp, required_tags)
                    self.resource_manager.update_resource(lsp)
                logger.info("The logical port for the VM %s has been tagged "
                            "with k8s cluster and node name.", vm_name)

    def configure_all(self):
        self.handle_transport_zone()
        self.handle_t0_router()
        self.handle_ipblocks()
        self.handle_vif()
        self.handle_t1_router()


def main():
    cmd_line_args = getargs()
    api_client = TinyClient(cmd_line_args)
    config_manager = ConfigurationManager(cmd_line_args, api_client)
    config_manager.configure_all()


if __name__ == '__main__':
    main()

