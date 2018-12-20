#!/usr/bin/python

# Copyright 2015 VMware Inc
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import optparse
import os
import sys

import requests
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class NSXClient(object):
    """Base NSX REST client"""

    def __init__(self, host, username, password, nsx_cert, key,
                 ca_cert, cluster, remove, t0_uuid, all_res):
        self.host = host
        self.username = username
        self.password = password
        self.nsx_cert = nsx_cert
        self.key = key
        self.use_cert = bool(self.nsx_cert and self.key)
        self.ca_cert = ca_cert
        self._cluster = cluster
        self._remove = remove
        self._t0_uuid = t0_uuid
        self._all_res = all_res
        self.resource_to_url = {
            'TransportZone': '/transport-zones',
            'LogicalRouter': '/logical-routers',
            'IpBlock': '/pools/ip-blocks',
            'IpPool': '/pools/ip-pools',
            'LogicalSwitch': '/logical-switches',
            'LogicalPort': '/logical-ports',
            'LogicalRouterPort': '/logical-router-ports',
            'VIF': '/fabric/vifs',
            'VM': '/fabric/virtual-machines',
            'LoadBalancerService': '/loadbalancer/services',
            'FirewallSection': '/firewall/sections',
            'NSGroup': '/ns-groups',
            'IPSets': '/ip-sets',
            'VirtualServer': '/loadbalancer/virtual-servers',
            'LoadBalancerRule': '/loadbalancer/rules',
            'LoadBalancerPool': '/loadbalancer/pools',
            'IPSubnets': '/pools/ip-subnets',
            'SwitchingProfile': '/switching-profiles',
            'Certificates': '/trust-management/certificates',
            'PersistenceProfile': '/loadbalancer/persistence-profiles'
        }
        self.header = {'X-Allow-Overwrite': 'true'}
        self.authenticate()
        self._t0 = self._get_tier0_routers()

    def _get_tier0_routers(self):
        if not self._t0_uuid:
            all_t0_routers = self.get_logical_routers(tier='TIER0')
            tier0_routers = self.get_ncp_resources(all_t0_routers)
        else:
            router_response = self.get_logical_routers_by_uuid(self._t0_uuid)
            if router_response.get('httpStatus') == 'NOT_FOUND':
                tier0_routers = []
            else:
                tier0_routers = [router_response]
        if not tier0_routers:
            raise Exception("Error: Missing cluster tier-0 router")
        if len(tier0_routers) > 1:
            raise Exception("Found %d tier-0 routers " % len(tier0_routers))
        return tier0_routers[0]

    def _resource_url(self, resource_type):
        return self.host + '/api/v1' + self.resource_to_url[resource_type]

    def make_get_call(self, full_url):
        if self.use_cert:
            return requests.get('https://' + full_url, cert=(self.nsx_cert,
                                                             self.key),
                                headers=self.header,
                                verify=False).json()
        else:
            return requests.get('https://' + full_url, auth=(self.username,
                                                             self.password),
                                headers=self.header,
                                verify=False).json()

    def make_post_call(self, full_url, body):
        if self.use_cert:
            return requests.post('https://' + full_url, cert=(self.nsx_cert,
                                                             self.key),
                                headers=self.header,
                                verify=False, json=body)
        else:
            return requests.post('https://' + full_url, auth=(self.username,
                                                             self.password),
                                headers=self.header,
                                verify=False, json=body)

    def make_delete_call(self, full_url):
        if self.use_cert:
            return requests.delete('https://' + full_url, cert=(self.nsx_cert,
                                                                self.key),
                                   headers=self.header,
                                   verify=False)
        else:
            return requests.delete('https://' + full_url, auth=(self.username,
                                                                self.password),
                                   headers=self.header,
                                   verify=False)

    def get_resource_by_type(self, resource_type):
        resource_url = self._resource_url(resource_type)
        print(resource_url)
        res = []
        r_json = self.make_get_call(resource_url)
        while 'cursor' in r_json:
            res += r_json['results']
            url_with_paging = resource_url + '?' + 'cursor=' + r_json['cursor']
            r_json = self.make_get_call(url_with_paging)
        res += r_json['results']
        return res

    def get_resource_by_type_and_id(self, resource_type, uuid):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        print(resource_url)
        return self.make_get_call(resource_url)

    def get_resource_by_query_param(self, resource_type, query_param_type,
                                    query_param_id):
        resource_url = self._resource_url(resource_type)
        full_url = (resource_url + '/?' +
                    query_param_type + '=' + query_param_id)
        print(full_url)
        return self.make_get_call(full_url)

    def get_resource_by_param(self, resource_type, param_type, param_val):
        resource_url = self._resource_url(resource_type)
        full_url = resource_url + '?' + param_type + '=' + param_val
        print(full_url)
        return self.make_get_call(full_url)

    def get_secondary_resource(self, resource_type, uuid, secondary_resource):
        resource_url = self._resource_url(resource_type)
        print(resource_url)
        full_url = resource_url + '/' + uuid + '/' + secondary_resource
        print(full_url)
        return self.make_get_call(full_url)

    def delete_secondary_resource_by_id(
            self, resource_type, uuid, secondary_resource, secondary_uuid):
        resource_url = self._resource_url(resource_type)
        full_url = (resource_url + '/' + uuid + '/' + secondary_resource +
                    '/' + secondary_uuid)
        print(full_url)
        res = self.make_delete_call(full_url)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)

    def delete_resource_by_type_and_id(self, resource_type, uuid):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        print(resource_url)
        res = self.make_delete_call(resource_url)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)

    def delete_resource_by_type_and_id_and_param(self, resource_type, uuid,
                                                 param_type, param_val):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        full_url = resource_url + '?' + param_type + '=' + param_val
        print(full_url)
        res = self.make_delete_call(full_url)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)

    # used to update with API calls: POST url/resource/uuid?para=para_val
    def update_resource_by_type_and_id_and_param(self, resource_type, uuid,
                                                 param_type, param_val, body):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        full_url = resource_url + '?' + param_type + '=' + param_val
        print(full_url)
        res = self.make_post_call(full_url, body)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)
        return res

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        return self.get_resource_by_type('LogicalPort')

    def get_ncp_logical_ports(self):
        """
        Retrieve all logical ports created by NCP
        """
        lports = self.get_ncp_resources(
            self.get_logical_ports())
        return lports

    def _cleanup_logical_ports(self, lports):
        # logical port vif detachment
        for lport in lports:
            if self.is_node_lsp(lport):
                continue
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'LogicalPort', lport['id'], 'detach', 'true')
            except Exception as e:
                print("ERROR: Failed to delete logical port %s, error %s" %
                      (lport['id'], e))
            else:
                print("Successfully deleted logical port %s" % lport['id'])

    def cleanup_ncp_logical_ports(self):
        """
        Delete all logical ports created by NCP
        """
        ncp_lports = self.get_ncp_logical_ports()
        print("Number of NCP Logical Ports to be deleted: %s" %
              len(ncp_lports))
        if not self._remove:
            return
        self._cleanup_logical_ports(ncp_lports)

    def is_node_lsp(self, lport):
        # Node LSP can be updated by NCP to be parent VIF type, but could also
        # be a normal VIF without context before NCP updates it
        if lport.get('attachment'):
            if (lport['attachment']['attachment_type'] == 'VIF' and
                (not lport['attachment']['context'] or
                 lport['attachment']['context']['vif_type'] == 'PARENT')):
                return True
        return False

    def _is_ncp_resource(self, tags):
        return any(tag.get('scope') == 'ncp/cluster' and
                   tag.get('tag') == self._cluster for tag in tags)

    def _is_ncp_ha_resource(self, tags):
        return any(tag.get('scope') == 'ncp/ha' and
                   tag.get('tag') == 'true' for tag in tags)

    def _is_ncp_shared_resource(self, tags):
        return any(tag.get('scope') == 'ncp/shared_resource' and
                   tag.get('tag') == 'true' for tag in tags)

    def get_ncp_resources(self, resources):
        """
        Get all logical resources created by NCP
        """
        ncp_resources = [r for r in resources if 'tags' in r
                         if self._is_ncp_resource(r['tags'])]
        return ncp_resources

    def get_ncp_shared_resources(self, resources):
        """
        Get all logical resources with ncp/cluster tag
        """
        ncp_shared_resources = [r for r in resources if 'tags' in r
                                if self._is_ncp_shared_resource(r['tags'])]
        return ncp_shared_resources

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        return self.get_resource_by_type('LogicalSwitch')

    def get_ncp_logical_switches(self):
        """
        Retrieve all logical switches created from NCP
        """
        lswitches = self.get_ncp_resources(
            self.get_logical_switches())

        return lswitches

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] == ls_id]

    def cleanup_ncp_logical_switches(self):
        """
        Delete all logical switches created from NCP
        """
        lswitches = self.get_ncp_logical_switches()
        print("Number of Logical Switches to be deleted: %s" %
              len(lswitches))
        for ls in lswitches:
            # Check if there are still ports on switch and blow them away
            # An example here is a metadata proxy port (this is not stored
            # in the DB so we are unable to delete it when reading ports
            # from the DB)
            lports = self.get_lswitch_ports(ls['id'])
            if lports:
                print("Number of orphan Logical Ports to be "
                      "deleted: %s for ls %s" % (len(lports),
                                                 ls['display_name']))
                if self._remove:
                    self._cleanup_logical_ports(lports)
            if not self._remove:
                continue
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'LogicalSwitch', ls['id'], 'cascade', 'true')
            except Exception as e:
                print("ERROR: Failed to delete logical switch %s-%s, "
                      "error %s" % (ls['display_name'], ls['id'], e))
            else:
                print("Successfully deleted logical switch %s-%s" %
                      (ls['display_name'], ls['id']))

            # Unconfigure nat rules in T0
            if 'ip_pool_id' not in ls:
                continue
            ip_pool_id = ls['ip_pool_id']
            try:
                ip_pool = self.get_resource_by_type_and_id('IpPool',
                                                           ip_pool_id)
            except Exception as e:
                # TODO: Needs to look into ncp log to see why
                # the pool is gone during k8s conformance test
                print("Failed to get ip_pool %s" % ip_pool_id)
                continue
            subnet, subnet_id = None, None
            for tag in ip_pool['tags']:
                if tag.get('scope') == "ncp/subnet":
                    subnet = tag.get('tag')
                if tag.get('scope') == "ncp/subnet_id":
                    subnet_id = tag.get('tag')

            # Remove router port to logical switch using router port client
            try:
                rep = self.get_resource_by_query_param(
                    'LogicalRouterPort', 'logical_switch_id', ls['id'])
                lp = rep['results']
                if lp:
                    self.delete_resource_by_type_and_id(
                        'LogicalRouterPort', lp['id'])
            except Exception as e:
                print("Failed to delete logical router port by logical "
                      "switch %s : %s" % (ls['display_name'], e))
            else:
                print("Successfully deleted logical router port by logical "
                      "switch %s" % ls['display_name'])

            if not subnet or not subnet_id:
                return
            t0_id = self._t0['id']
            print("Unconfiguring nat rules for %s from t0" % subnet)
            try:
                snat_rules = self.get_secondary_resource(
                    'LogicalRouter', t0_id, 'nat/rules')
                ncp_snat_rules = self.get_ncp_resources(snat_rules['results'])
                ncp_snat_rule = None
                for snat_rule in ncp_snat_rules:
                    if snat_rule['match_source_network'] == subnet:
                        ncp_snat_rule = snat_rule
                        break
                self.release_snat_external_ip(ncp_snat_rule)
                self.delete_secondary_resource_by_id(
                    'LogicalRouter', t0_id, 'nat/rules', ncp_snat_rule['id'])
            except Exception as e:
                print("ERROR: Failed to unconfigure nat rule for %s "
                      "from t0: %s" % (subnet, e))
            else:
                print("Successfully unconfigured nat rule for %s "
                      "from t0" % subnet)

            # Finally delete the subnet and ip_pool
            try:
                print("Deleting ip_pool %s" % ip_pool['display_name'])
                self._cleanup_ip_pool(ip_pool)
                print("Deleting IP block subnet %s" % subnet)
                self.delete_resource_by_type_and_id('IPSubnets', subnet_id)
            except Exception as e:
                print("ERROR: Failed to delete %s, error %s" %
                      (subnet, e))
            else:
                print("Successfully deleted subnet %s" % subnet)

    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        return self.get_resource_by_type('FirewallSection')

    def get_ncp_firewall_sections(self):
        """
        Retrieve all firewall sections created from NCP
        """
        fw_sections = self.get_ncp_resources(
            self.get_firewall_sections())
        return fw_sections

    def cleanup_ncp_firewall_sections(self):
        """
        Cleanup all firewall sections created from NCP
        """
        fw_sections = self.get_ncp_firewall_sections()
        print("Number of Firewall Sections to be deleted: %s" %
              len(fw_sections))
        if not self._remove:
            return
        for fw in fw_sections:
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'FirewallSection', fw['id'], 'cascade', 'true')
            except Exception as e:
                print("Failed to delete firewall section %s: %s" %
                      (fw['display_name'], e))
            else:
                print("Successfully deleted firewall section %s" %
                      fw['display_name'])

    def get_ns_groups(self):
        return self.get_resource_by_type('NSGroup')

    def get_ns_ncp_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        ns_groups = self.get_ncp_resources(self.get_ns_groups())
        return ns_groups

    def cleanup_ncp_ns_groups(self):
        """
        Cleanup all NSGroups created by NCP
        """
        ns_groups = self.get_ns_ncp_groups()
        print("Number of NSGroups to be deleted: %s" % len(ns_groups))
        if not self._remove:
            return
        for nsg in ns_groups:
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'NSGroup', nsg['id'], 'force', 'true')
            except Exception as e:
                print("Failed to delete NSGroup: %s: %s" %
                      (nsg['display_name'], e))
            else:
                print("Successfully deleted NSGroup: %s" %
                      nsg['display_name'])

    def _escape_data(self, data):
        # ElasticSearch query_string requires slashes and dashes to
        # be escaped. We assume no other reserved character will be
        # used in tag scopes or values
        return data.replace('/', '\\/').replace('-', '\\-')

    def get_ip_sets(self):
        return self.get_resource_by_type('IPSets')

    def get_ncp_ip_sets(self):
        ip_sets = self.get_ncp_resources(self.get_ip_sets())
        return ip_sets

    def cleanup_ncp_ip_sets(self):
        """
        Cleanup all IP Sets created by NCP
        """
        ip_sets = self.get_ncp_ip_sets()
        print("Number of IP-Sets to be deleted: %d" % len(ip_sets))
        if not self._remove:
            return
        for ip_set in ip_sets:
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'IPSets', ip_set['id'], 'force', 'true')
            except Exception as e:
                print("Failed to delete IPSet: %s: %s" %
                      (ip_set['display_name'], e))
            else:
                print("Successfully deleted IPSet: %s" %
                      ip_set['display_name'])

    def get_logical_routers(self, tier=None):
        """
        Retrieve all the logical routers based on router type. If tier
        is None, it will return all logical routers.
        """
        lrouters = self.get_resource_by_type('LogicalRouter')
        if tier:
            lrouters = [router for router in lrouters
                        if router['router_type'] == tier]
        return lrouters

    def get_logical_routers_by_uuid(self, uuid):
        """
        Retrieve the logical router with specified UUID.
        """
        return self.get_resource_by_type_and_id('LogicalRouter', uuid)

    def get_ncp_logical_routers(self):
        """
        Retrieve all logical routers created from Neutron NSXv3 plugin
        """
        lrouters = self.get_logical_routers()
        return self.get_ncp_resources(lrouters)

    def get_logical_router_ports(self, lrouter):
        """
        Get all logical ports attached to lrouter
        """
        return self.get_resource_by_param('LogicalRouterPort',
                                          'logical_router_id',
                                          lrouter['id'])['results']

    def get_ncp_logical_router_ports(self, lrouter):
        """
        Retrieve all logical router ports created from Neutron NSXv3 plugin
        """
        lports = self.get_logical_router_ports(lrouter)
        return self.get_ncp_resources(lports)

    def cleanup_logical_router_ports(self, lrouter):
        """
        Cleanup all logical ports on a logical router
        """
        lports = self.get_ncp_logical_router_ports(lrouter)
        print("Number of logical router ports to be deleted: %s" % len(lports))
        if not self._remove:
            return
        for lp in lports:
            try:
                self.delete_resource_by_type_and_id(
                    'LogicalRouterPort', lp['id'])
            except Exception as e:
                print("Failed to delete logical router port %s-%s, "
                      "and response is %s" %
                      (lp['display_name'], lp['id'], e))
            else:
                print("Successfully deleted logical router port %s-%s" %
                      (lp['display_name'], lp['id']))

    def release_logical_router_external_ip(self, lr):
        external_ip = None
        external_pool_id = None
        if 'tags' in lr:
            for tag in lr['tags']:
                if tag.get('scope') == 'ncp/extpoolid':
                    external_pool_id = tag.get('tag')
                if tag.get('scope') == 'ncp/snat_ip':
                    external_ip = tag.get('tag')
        if not external_pool_id:
            return
        if not external_ip:
            return
        print("External ip %s to be released from pool %s" %
              (external_ip, external_pool_id))
        if not self._remove:
            return
        try:
            body = {"allocation_id": external_ip}
            self.update_resource_by_type_and_id_and_param(
                'IpPool', external_pool_id, 'action', 'RELEASE',
                body=body)
        except Exception as e:
            print("ERROR: Failed to release ip %s from external_pool %s, "
                  "error %s" % (external_ip, external_pool_id, e))
        else:
            print("Successfully release ip %s from external_pool %s"
                  % (external_ip, external_pool_id))

    def release_snat_external_ip(self, snat_rule):
        print("Releasing translated_network for snat %s" % snat_rule['id'])
        external_pool_id = None
        if 'tags' in snat_rule:
            for tag in snat_rule['tags']:
                if tag.get('scope') == 'ncp/extpoolid':
                    external_pool_id = tag.get('tag')
                    break
        if not external_pool_id:
            return
        external_ip = snat_rule.get('translated_network')
        if not external_ip:
            return
        print("External ip %s to be released from pool %s" %
              (external_ip, external_pool_id))
        if not self._remove:
            return
        try:
            body = {"allocation_id": external_ip}
            self.update_resource_by_type_and_id_and_param(
                'IpPool', external_pool_id, 'action', 'RELEASE',
                body=body)
        except Exception as e:
            print("ERROR: Failed to release ip %s from external_pool %s, "
                  "error %s" % (external_ip, external_pool_id, e))
        else:
            print("Successfully release ip %s from external_pool %s"
                  % (external_ip, external_pool_id))

    def cleanup_ncp_logical_routers(self):
        """
        Delete all logical routers created by NCP
        To delete a logical router, we need to delete all logical
        ports on the router first.
        We also need to release the ip assigned from external pool
        """
        lrouters = self.get_ncp_logical_routers()
        print("Number of Logical Routers to be deleted: %s" %
              len(lrouters))
        for lr in lrouters:
            self.cleanup_logical_router_ports(lr)
            self.release_logical_router_external_ip(lr)
            if not self._remove:
                continue
            if lr['router_type'] == 'TIER0':
                continue
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'LogicalRouter', lr['id'], 'force', 'true')
            except Exception as e:
                print("ERROR: Failed to delete logical router %s-%s, "
                      "error %s" % (lr['display_name'], lr['id'], e))
            else:
                print("Successfully deleted logical router %s-%s" %
                      (lr['display_name'], lr['id']))

    def cleanup_ncp_router_ports(self):
        ncp_router_ports = self.get_ncp_resources(
            self.get_resource_by_type('LogicalRouterPort'))
        print("Number of orphane logical router ports to be deleted %d"
              % len(ncp_router_ports))
        if not self._remove:
            return
        for router_port in ncp_router_ports:
            try:
                self.delete_resource_by_type_and_id_and_param(
                    'LogicalRouterPort', router_port['id'], 'force', 'true')
            except Exception as e:
                print("Failed to delete logical router port %s-%s, "
                      "and response is %s" %
                      (router_port['display_name'], router_port['id'], e))
            else:
                print("Successfully deleted logical router port %s-%s" %
                      (router_port['display_name'], router_port['id']))

    def cleanup_ncp_tier0_logical_ports(self):
        """
        Delete all TIER0 logical router ports created by NCP
        Followed the same logic in delete_project in nsxapi
        """
        tier1_routers = self.get_ncp_resources(
            self.get_logical_routers(tier='TIER1'))
        t0 = self._t0
        for t1 in tier1_routers:
            print("Router link port from %s to %s to be removed" %
                  (t0['display_name'], t1['display_name']))
            try:
                self.remove_router_link_port(t1['id'])
            except Exception as e:
                print("Error removing router link port from %s to %s" %
                      (t0['display_name'], t1['display_name']), e)
            else:
                if not self._remove:
                    continue
                print("successfully remove link port for %s and %s" %
                      (t1['display_name'], t0['display_name']))

    def get_tier1_link_port(self, t1_uuid):
        logical_router_ports = self.get_resource_by_param(
            'LogicalRouterPort', 'logical_router_id', t1_uuid)['results']
        for port in logical_router_ports:
            if port['resource_type'] == 'LogicalRouterLinkPortOnTIER1':
                return port

    def remove_router_link_port(self, t1_uuid):
        tier1_link_port = self.get_tier1_link_port(t1_uuid)
        if not tier1_link_port:
            print("Warning: Logical router link port for tier1 router: %s "
                  "not found at the backend", t1_uuid)
            return
        t1_link_port_id = tier1_link_port['id']
        t0_link_port_id = (
            tier1_link_port['linked_logical_router_port_id'].get('target_id'))
        print("Removing t1_link_port %s" % t1_link_port_id)
        print("Removing t0_link_port %s" % t0_link_port_id)
        if not self._remove:
            return
        self.delete_resource_by_type_and_id(
            'LogicalRouterPort', t1_link_port_id)
        self.delete_resource_by_type_and_id(
            'LogicalRouterPort', t0_link_port_id)

    def get_ip_pools(self):
        """
        Retrieve all ip_pools on NSX backend
        """
        return self.get_resource_by_type('IpPool')

    def get_ncp_get_ip_pools(self):
        """
        Retrieve all logical switches created from NCP
        """
        ip_pools = self.get_ncp_resources(
            self.get_ip_pools())

        return ip_pools

    def _cleanup_ip_pool(self, ip_pool):
        if not ip_pool:
            return
        allocations = self.get_secondary_resource('IpPool', ip_pool['id'],
                                                  'allocations')
        print("Number of IPs to be released %s" % len(allocations))
        if 'results' in allocations:
            for allocation in allocations['results']:
                allocated_ip = allocation['allocation_id']
                body = {"allocation_id": allocated_ip}
                try:
                    self.update_resource_by_type_and_id_and_param(
                        'IpPool', ip_pool['id'], 'action', 'RELEASE',
                        body=body)
                except Exception as e:
                    print("ERROR: Failed to release ip %s from Ip pool %s "
                          "error: %s" % (allocated_ip, ip_pool['id'], e))
        self.delete_resource_by_type_and_id_and_param('IpPool', ip_pool['id'],
                                                      'force', 'true')

    def cleanup_ncp_ip_pools(self):
        """
        Delete all ip pools created from NCP
        """
        ip_pools = self.get_ncp_get_ip_pools()
        print("Number of IP Pools to be deleted: %s" %
              len(ip_pools))
        if not self._remove:
            return
        for ip_pool in ip_pools:
            if 'tags' in ip_pool:
                is_external = False
                for tag in ip_pool['tags']:
                    if (tag.get('scope') == 'ncp/external' and
                        tag.get('tag') == 'true'):
                        is_external = True
                        break
                if is_external:
                    continue
            try:
                self._cleanup_ip_pool(ip_pool)
            except Exception as e:
                print("ERROR: Failed to delete ip pool %s:%s, "
                      "error %s" % (ip_pool['display_name'],
                                    ip_pool['id'], e))
            else:
                print("Successfully deleted ip pool %s-%s" %
                      (ip_pool['display_name'], ip_pool['id']))

    def cleanup_ncp_lb_services(self):
        lb_services = self.get_ncp_lb_services()
        print("Number of Loadbalance services to be deleted: %s" %
              len(lb_services))
        if not self._remove:
            return
        for lb_svc in lb_services:
            try:
                self.delete_resource_by_type_and_id('LoadBalancerService',
                                                    lb_svc['id'])
            except Exception as e:
                print("ERROR: Failed to delete lb_service %s-%s, error %s" %
                      (lb_svc['display_name'], lb_svc['id'], e))
            else:
                print("Successfully deleted lb_service %s-%s" %
                      (lb_svc['display_name'], lb_svc['id']))

    def get_ncp_lb_services(self):
        lb_services = self.get_lb_services()
        return self.get_ncp_resources(lb_services)

    def get_lb_services(self):
        return self.get_resource_by_type('LoadBalancerService')

    def cleanup_ncp_lb_virtual_servers(self):
        lb_virtual_servers = self.get_ncp_lb_virtual_servers()
        print("Number of loadbalancer virtual servers to be deleted: %s" %
              len(lb_virtual_servers))
        for lb_vs in lb_virtual_servers:
            self.release_lb_virtual_server_external_ip(lb_vs)
            if not self._remove:
                continue
            try:
                self.delete_resource_by_type_and_id('VirtualServer',
                                                    lb_vs['id'])
            except Exception as e:
                print("ERROR: Failed to delete lv_virtual_server %s-%s, "
                      "error %s" % (lb_vs['display_name'], lb_vs['id'], e))
            else:
                print("Successfully deleted lv_virtual_server %s-%s" %
                      (lb_vs['display_name'], lb_vs['id']))

    def release_lb_virtual_server_external_ip(self, lb_vs):
        if 'ip_address' not in lb_vs:
            return
        external_ip = lb_vs['ip_address']
        external_pool_id = None
        if 'tags' in lb_vs:
            for tag in lb_vs['tags']:
                if tag.get('scope') == 'ext_pool_id':
                    external_pool_id = tag.get('tag')
        if not external_pool_id:
            return

        print("Releasing external IP %s-%s "
              "of lb virtual server %s from external pool %s" %
              (lb_vs['display_name'], lb_vs['id'],
               external_ip, external_pool_id))
        if not self._remove:
            return
        try:
            body = {"allocation_id": external_ip}
            self.update_resource_by_type_and_id_and_param(
                'IpPool', external_pool_id, 'action', 'RELEASE',
                body=body)
        except Exception as e:
            print("ERROR: Failed to release ip %s from external_pool %s, "
                  "error %s" % (external_ip, external_pool_id, e))
        else:
            print("Successfully release ip %s from external_pool %s"
                  % (external_ip, external_pool_id))

    def get_ncp_lb_virtual_servers(self):
        lb_virtual_servers = self.get_virtual_servers()
        return self.get_ncp_resources(lb_virtual_servers)

    def get_virtual_servers(self):
        return self.get_resource_by_type('VirtualServer')

    def cleanup_ncp_lb_rules(self):
        lb_rules = self.get_ncp_lb_rules()
        print("Number of loadbalancer rules to be deleted: %s" %
              len(lb_rules))
        if not self._remove:
            return
        for lb_rule in lb_rules:
            try:
                self.delete_resource_by_type_and_id('LoadBalancerRule',
                                                    lb_rule['id'])
            except Exception as e:
                print("ERROR: Failed to delete lb_rule %s-%s, "
                      "error %s" % (lb_rule['display_name'],
                                    lb_rule['id'], e))
            else:
                print("Successfully deleted lb_rule %s-%s" %
                      (lb_rule['display_name'], lb_rule['id']))

    def get_ncp_lb_rules(self):
        lb_rules = self.get_lb_rules()
        return self.get_ncp_resources(lb_rules)

    def get_lb_rules(self):
        return self.get_resource_by_type('LoadBalancerRule')

    def cleanup_ncp_lb_pools(self):
        lb_pools = self.get_ncp_lb_pools()
        print("Number of loadbalancer pools to be deleted: %s" %
              len(lb_pools))
        if not self._remove:
            return
        for lb_pool in lb_pools:
            try:
                self.delete_resource_by_type_and_id('LoadBalancerPool',
                                                    lb_pool['id'])
            except Exception as e:
                print("ERROR: Failed to delete lb_pool %s-%s, "
                      "error %s" % (lb_pool['display_name'],
                                    lb_pool['id'], e))
            else:
                print("Successfully deleted lb_pool %s-%s" %
                      (lb_pool['display_name'], lb_pool['id']))

    def get_ncp_lb_pools(self):
        lb_pools = self.get_lb_pools()
        return self.get_ncp_resources(lb_pools)

    def get_lb_pools(self):
        return self.get_resource_by_type('LoadBalancerPool')

    def cleanup_ncp_persistence_profiles(self):
        persistence_profiles = self.get_ncp_persistence_profiles()
        print("Number of persistence profiles rules to be deleted: %s" %
              len(persistence_profiles))
        if not self._remove:
            return
        for persistence_profile in persistence_profiles:
            try:
                self.delete_resource_by_type_and_id('PersistenceProfile',
                                                    persistence_profile['id'])
            except Exception as e:
                print("ERROR: Failed to delete persistence profile %s-%s, "
                      "error %s" % (persistence_profile['display_name'],
                                    persistence_profile['id'], e))
            else:
                print("Successfully deleted persistence profile %s-%s" %
                      (persistence_profile['display_name'],
                       persistence_profile['id']))

    def get_ncp_persistence_profiles(self):
        return self.get_ncp_resources(
            self.get_resource_by_type('PersistenceProfile'))

    def get_ip_blocks(self):
        return self.get_resource_by_type('IpBlock')

    def get_ncp_ip_blocks(self):
        ip_blocks = self.get_ip_blocks()
        return self.get_ncp_resources(ip_blocks)

    def get_switching_profiles(self):
        sw_profiles = self.get_resource_by_type('SwitchingProfile')
        return sw_profiles

    def get_ncp_switching_profiles(self):
        sw_profiles = self.get_switching_profiles()
        return self.get_ncp_resources(sw_profiles)

    def get_l7_resource_certs(self):
        return self.get_resource_by_type('Certificates')

    def get_ncp_l7_resource_certs(self):
        l7_resource_certs = self.get_l7_resource_certs()
        return self.get_ncp_resources(l7_resource_certs)

    def cleanup_cert(self):
        if self.nsx_cert and self.key:
            try:
                os.close(self.fd)
                os.remove(self.certpath)
                print("Certificate file %s for NSX client connection "
                      "has been removed" % self.certpath)
            except OSError as e:
                print("Error when during cert file cleanup %s" % e)

    def cleanup_ncp_snat_rules(self):
        t0 = self._t0
        snat_rules = self.get_secondary_resource(
            'LogicalRouter', t0['id'], 'nat/rules')
        ncp_snat_rules = self.get_ncp_resources(snat_rules['results'])
        print("Number of snat rules to be deleted: %s" %
              len(ncp_snat_rules))
        if not self._remove:
            return
        for snat_rule in ncp_snat_rules:
            print(snat_rule)
            try:
                self.release_snat_external_ip(snat_rule)
                self.delete_secondary_resource_by_id(
                    'LogicalRouter', t0['id'], 'nat/rules', snat_rule['id'])
            except Exception as e:
                print("ERROR: Failed to delete snat_rule for %s-%s, "
                      "error %s" % (snat_rule['translated_network'],
                                    snat_rule['id'], e))
            else:
                print("Successfully deleted snat_rule for %s-%s" %
                      (snat_rule['translated_network'], snat_rule['id']))

    def cleanup_ncp_ip_blocks(self):
        ip_blocks = self.get_ncp_ip_blocks()
        print("Number of ip blocks to be deleted: %s" %
              len(ip_blocks))
        if not self._remove:
            return
        for ip_block in ip_blocks:
            try:
                self.delete_resource_by_type_and_id('IpBlock',
                                                    ip_block['id'])
            except Exception as e:
                print("ERROR: Failed to delete ip_block %s-%s, "
                      "error %s" % (ip_block['display_name'],
                                    ip_block['id'], e))
            else:
                print("Successfully deleted ip_block %s-%s" %
                      (ip_block['display_name'], ip_block['id']))

    def cleanup_ncp_switching_profiles(self):
        ncp_switching_profiles = self.get_ncp_switching_profiles()
        print("Number of switching profiles to be deleted: %s" %
              len(ncp_switching_profiles))
        if not self._remove:
            return
        for switching_profile in ncp_switching_profiles:
            try:
                self.delete_resource_by_type_and_id('SwitchingProfile',
                                                    switching_profile['id'])
            except Exception as e:
                print("ERROR: Failed to delete switching_profile %s-%s, "
                      "error %s" % (switching_profile['display_name'],
                                    switching_profile['id'], e))
            else:
                print("Successfully deleted switching_profile %s-%s" %
                      (switching_profile['display_name'],
                       switching_profile['id']))

    def cleanup_ncp_external_ip_pools(self):
        """
        Delete all external ip pools created from NCP
        """
        ip_pools = self.get_ncp_get_ip_pools()
        external_ip_pools = []
        for ip_pool in ip_pools:
            if 'tags' in ip_pool:
                for tag in ip_pool['tags']:
                    if (tag.get('scope') == 'ncp/external' and
                        tag.get('tag') == 'true'):
                        external_ip_pools.append(ip_pool)
        print("Number of external IP Pools to be deleted: %s" %
              len(external_ip_pools))
        if not self._remove:
            return

        for ext_ip_pool in external_ip_pools:
            try:
                self._cleanup_ip_pool(ext_ip_pool)
            except Exception as e:
                print("ERROR: Failed to delete external ip pool %s:%s, "
                      "error %s" % (ext_ip_pool['display_name'],
                                    ext_ip_pool['id'], e))
            else:
                print("Successfully deleted external ip pool %s-%s" %
                      (ext_ip_pool['display_name'], ext_ip_pool['id']))

    def cleanup_ncp_l7_resource_certs(self):
        l7_resource_certs = self.get_ncp_l7_resource_certs()
        print("Number of l7 resource certs to be deleted: %s" %
              len(l7_resource_certs))
        if not self._remove:
            return
        for l7_resource_cert in l7_resource_certs:
            try:
                self.delete_resource_by_type_and_id('Certificates',
                                                    l7_resource_cert['id'])
            except Exception as e:
                print("ERROR: Failed to delete l7_resource_cert %s-%s, "
                      "error %s" % (l7_resource_cert['display_name'],
                                    l7_resource_cert['id'], e))
            else:
                print("Successfully deleted l7_resource_cert %s-%s" %
                      (l7_resource_cert['display_name'],
                       l7_resource_cert['id']))

    def authenticate(self):
        # make a get call to make sure response is not forbidden
        full_url = self._resource_url('TransportZone')
        if self.use_cert:
            response = requests.get('https://' + full_url, cert=(self.nsx_cert,
                                                                 self.key),
                                headers=self.header,
                                verify=False)
        else:
            response = requests.get('https://' + full_url,
                                    auth=(self.username, self.password),
                                    headers=self.header,
                                    verify=False)
        if response.status_code == requests.codes.forbidden:
            print("ERROR: Authentication failed! "
                  "Please check your credentials.")
            exit(1)

    def cleanup_all(self):
        """
        Cleanup steps:
            1. Cleanup firewall sections
            2. Cleanup NSGroups
            3. Cleanup logical router ports
            4. Cleanup logical routers
            5. Cleanup logical switch ports
            6. Cleanup logical switches
            7. Cleanup switching profiles
            8. Cleanup loadbalancer services
            9. Cleanup loadbalancer virtual servers
            10.Cleanup loadbalancer rules
            11.Cleanup loadbalancer pools
            12.Cleanup ip pools
        """
        self.cleanup_ncp_firewall_sections()
        self.cleanup_ncp_ns_groups()
        self.cleanup_ncp_ip_sets()
        self.cleanup_ncp_lb_services()
        self.cleanup_ncp_lb_virtual_servers()
        self.cleanup_ncp_lb_rules()
        self.cleanup_ncp_lb_pools()
        self.cleanup_ncp_persistence_profiles()
        self.cleanup_ncp_tier0_logical_ports()
        self.cleanup_ncp_logical_ports()
        self.cleanup_ncp_logical_routers()
        self.cleanup_ncp_router_ports()
        self.cleanup_ncp_logical_switches()
        self.cleanup_ncp_snat_rules()
        self.cleanup_ncp_ip_pools()
        self.cleanup_ncp_l7_resource_certs()
        self.cleanup_ncp_switching_profiles()
        if self._all_res:
            self.cleanup_ncp_ip_blocks()
            self.cleanup_ncp_external_ip_pools()


def validate_options(options):
    if not options.mgr_ip or not options.cluster:
        print("Required arguments missing. Run '<script_name> -h' for usage")
        sys.exit(1)
    if (not options.password and not options.username and
        not options.nsx_cert and not options.key):
        print("Required authentication parameter missing. "
              "Run '<script_name> -h' for usage")
        sys.exit(1)

if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="", dest="username",
                      help="NSX Manager username, ignored if nsx-cert is set")
    parser.add_option("-p", "--password", default="",
                      dest="password",
                      help="NSX Manager password, ignored if nsx-cert is set")
    parser.add_option("-n", "--nsx-cert", default="", dest="nsx_cert",
                      help="NSX certificate path")
    parser.add_option("-k", "--key", default="", dest="key",
                      help="NSX client private key path")
    parser.add_option("-c", "--cluster", dest="cluster",
                      help="Cluster to be removed")
    parser.add_option("-t", "--ca-cert", default="", dest="ca_cert",
                      help="NSX ca_certificate")
    parser.add_option("-r", "--remove", action='store_true',
                      dest="remove", help="CAVEAT: Removes NSX resources. "
                                          "If not set will do dry-run.")
    parser.add_option("--t0-uuid", dest="t0_uuid",
                      help="Specify the tier-0 router uuid. Must be "
                           "specified if Tier-0 router does not have the "
                           "cluster tag")
    parser.add_option("--all-res", dest="all_res",
                      help=("Also clean up HA switching profile, ipblock, "
                            "external ippool. These resources could be "
                            "created by PAS NSX-T Tile"), action='store_true')
    parser.add_option("--no-warning", action="store_true", dest="no_warning",
                      help="Disable urllib's insecure request warning")
    (options, args) = parser.parse_args()

    if options.no_warning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

    validate_options(options)
    # Get NSX REST client
    nsx_client = NSXClient(host=options.mgr_ip,
                           username=options.username,
                           password=options.password,
                           nsx_cert=options.nsx_cert,
                           key=options.key,
                           ca_cert=options.ca_cert,
                           cluster=options.cluster,
                           remove=options.remove,
                           t0_uuid=options.t0_uuid,
                           all_res=options.all_res)
    nsx_client.cleanup_all()
