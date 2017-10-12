#*************************************************************************
# Copyright (c) 2017 VMware, Inc. All rights reserved.VMware Confidential.
#*************************************************************************
#!/usr/bin/python
'''
Created on Jun 8, 2017
@author: yfan, skai
'''

import argparse
import base64
import httplib
import json
import logging
import ssl
import sys
from urllib import urlencode

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
        self.mp_ip = args.mp_ip
        self.mp_user = args.mp_user
        self.mp_password = args.mp_password
        self.port = 443
        self.mp_cert_file = args.mp_cert_file

        self.content_type = "application/json"
        self.accept_type = "application/json"
        self.response = None
        self.url_prefix = "/api/" + self.DEFAULT_VERSION
        self.headers = {'content-type': self.content_type}
        # use basic auth if cert file is not specified
        if not self.mp_cert_file:
            auth = base64.urlsafe_b64encode(
                self.mp_user + ':' + self.mp_password).decode('ascii')
            self.headers['Authorization'] = 'Basic %s' % auth
            self._connect_with_pwd()
        else:
            self._connect_with_cert()

    def _connect_with_cert(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.load_cert_chain(self.mp_cert_file)
        self.connection = httplib.HTTPSConnection(self.mp_ip,
                                                  self.port,
                                                  timeout=30000,
                                                  context=ctx)

    def _connect_with_pwd(self):
        if sys.version_info >= (2, 7, 9):
            ctx = ssl._create_unverified_context()
            self.connection = httplib.HTTPSConnection(self.mp_ip,
                                                      self.port,
                                                      timeout=30000,
                                                      context=ctx)
        else:
            self.connection = httplib.HTTPSConnection(self.mp_ip, self.port,
                                                      timeout=30000)

    def close(self):
        self.connection.close()

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
        request = "%s%s%s" % (self.url_prefix, endpoint, url_params_string)
        logger.info('request: %s', request)
        self.connection.request(method, request, payload, self.headers)
        self.response = self.connection.getresponse()
        return self.response

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
        response = self._request(method, endpoint, payload,
                                 url_parameters=params)
        # object not found
        if method == 'GET' and response.status == 404:
            return None
        result_string = response.read()

        logger.info('response: %s', result_string)
        # DELETE response body is empty
        py_dict = json.loads(result_string) if result_string else {}
        logger.info('reponse: %s', py_dict)

        if (response.status < 200 or response.status >= 300 or
                "error_code" in py_dict):
            raise Exception(py_dict)
        else:
            return py_dict

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
        search_url = '/search'
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

    parser.add_argument('--snat_ipblock_name',
                        dest="snat_ipblock_name",
                        default='',
                        help='name of IpBlock for SNAT')
    parser.add_argument('--snat_ipblock_cidr',
                        dest="snat_ipblock_cidr",
                        default="",
                        help='CIDR of IpBlock for SNAT')

    parser.add_argument('--mac',
                        dest="mac_list",
                        default="",
                        help='MAC address of kubernetes nodes with the first '
                             'as master node split by "," no spaces. Format: '
                             'vm1,vm2,vm3.')
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


class NSXResourceManager(object):
    def __init__(self, api_client):
        self.api_client = api_client

        self.resource_to_url = {
            'TransportZone': '/transport-zones',
            'LogicalRouter': '/logical-routers',
            'IpBlock': '/pools/ip-blocks',
            'LogicalSwitch': '/logical-switches',
            'LogicalPort': '/logical-ports',
        }

    def get_resource_by_type_and_name(self, resource_type, resource_name):
        search_params = {
            'resource_type': resource_type,
            'display_name': resource_name,
        }
        response = self.api_client.search(search_params)
        result_count = response.get('result_count', 0)
        if result_count > 1:
            raise Exception('More than one resource found for type %s and '
                            'name %s', resource_type, resource_name)
        return response['results'][0] if result_count else None

    def get_or_create_resource(self, resource_type, resource_name,
                               params=None):
        resource = self.get_resource_by_type_and_name(
            resource_type, resource_name)
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


class ConfigurationManager(object):
    def __init__(self, args, api_client):
        self.resource_manager = NSXResourceManager(api_client)

        self.manager_ip = args.mp_ip
        self.username = args.mp_user
        self.password = args.mp_password

        self.cluster_name = args.k8scluster
        self.transport_zone_name = args.tz

        self.t0_router_name = args.t0
        self.edge_cluster_name = args.edge_cluster

        self.pod_ipblock_name = args.pod_ipblock_name
        self.pod_ipblock_cidr = args.pod_ipblock_cidr
        self.snat_ipblock_name = args.snat_ipblock_name
        self.snat_ipblock_cidr = args.snat_ipblock_cidr

        self.mac_to_node_name = self._parse_mac_to_node_name(args)
        self.node_ls_name = args.node_ls

    def _parse_mac_to_node_name(self, args):
        mac_list = args.mac_list.split(',')
        node_name_list = args.node_list.split(',')
        mapping = {}
        for mac, node_name in zip(mac_list, node_name_list):
            mapping[mac] = node_name
        return mapping

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
                                      params=None, required_tags=None):
        """
        The algorithm for 'general configuration' is: Check if the resource
        with specified type and name exists and only one exists.
        Raise an exception if more than one resources found.
        If not found, create one.
        Then continue and tag the resource if it doesn't yet have all of the
        required tags.
        """

        resource = self.resource_manager.get_or_create_resource(
            resource_type, resource_name, params)
        if not self._has_tags(resource, required_tags):
            resource = add_tag(resource, required_tags)
            self.resource_manager.update_resource(resource)

    def handle_transport_zone(self):
        params = {
            'host_switch_name': 'nsxvswitch',
            'transport_type': 'OVERLAY',
        }
        required_tags = {NCP_CLUSTER_KEY: self.cluster_name}
        self._handle_general_configuration(
            'TransportZone', self.transport_zone_name, params, required_tags)

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
            'LogicalRouter', self.t0_router_name, params, required_tags)

    def _handle_ipblock(self, ipblock_name, ipblock_cidr, required_tags):
        # handle ipblock configuration for a specific block name
        params = {'cidr': ipblock_cidr}
        self._handle_general_configuration(
            'IpBlock', ipblock_name, params, required_tags)

    def handle_ipblocks(self):
        # IP block for pod traffic
        self._handle_ipblock(self.pod_ipblock_name, self.pod_ipblock_cidr, {
            NCP_CLUSTER_KEY: self.cluster_name})

        # IP block for SNAT
        self._handle_ipblock(self.snat_ipblock_name, self.snat_ipblock_cidr, {
            NCP_EXTERNAL_KEY: 'true'})

    def handle_vif(self):
        # get node-ls. Create it if it doesn't exist yet
        transport_zone = self.resource_manager.get_resource_by_type_and_name(
            'TransportZone', self.transport_zone_name)

        params = {
            'transport_zone_id': transport_zone['id'],
            'admin_state': 'UP',
            'replication_mode': 'MTEP',
        }
        node_ls = self.resource_manager.get_or_create_resource(
            'LogicalSwitch', self.node_ls_name, params)

        logger.info('node_ls: %s', node_ls)

        logical_ports = self.resource_manager.get_all(
            'LogicalPort', {'logical_switch_id': node_ls['id']})

        for port in logical_ports:
            port_id = port['id']

            mac_table = []
            try:
                mac_table = self.resource_manager.get_mac_table_for_lp(port_id)
            except Exception:
                logger.warning('Unable to obtain mac_table for logical port '
                               '%s with id %s', port['display_name'],
                               port['id'])

            matched_mac = None
            for mac_entry in mac_table:
                mac = mac_entry['mac_address']
                if mac and mac in self.mac_to_node_name:
                    matched_mac = mac
                    break

            if not mac_table or not matched_mac:
                logger.info('Logical port %s does not have a matched mac',
                            port['display_name'])
                continue

            node_name = self.mac_to_node_name[matched_mac]
            # tag it with the node name
            required_tags = {
                NCP_CLUSTER_KEY: self.cluster_name,
                NCP_NODE_KEY: node_name
            }
            logger.info('required tags: %s, port: %s', required_tags, port)
            if not self._has_tags(port, required_tags):
                port = add_tag(port, required_tags)
                self.resource_manager.update_resource(port)

    def configure_all(self):
        self.handle_transport_zone()
        self.handle_t0_router()
        self.handle_ipblocks()
        self.handle_vif()


def main():
    cmd_line_args = getargs()
    api_client = TinyClient(cmd_line_args)
    config_manager = ConfigurationManager(cmd_line_args, api_client)
    config_manager.configure_all()
    api_client.close()


if __name__ == '__main__':
    main()
