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
import tempfile

from vmware_nsxlib import v3  # noqa
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import config  # noqa
from vmware_nsxlib.v3 import resources
from vmware_nsxlib.v3 import router


class NSXClient(object):
    """Base NSX REST client"""

    def __init__(self, host, username, password, nsx_cert, key,
                 ca_cert, cluster, read_only, shared_t0):
        self.host = host
        self.username = username
        self.password = password
        self.nsx_cert = nsx_cert
        self.key = key
        self.ca_cert = ca_cert
        cert_provider = None
        insecure = True
        if nsx_cert and key:
            self.fd, self.certpath = tempfile.mkstemp(dir='/tmp')
            cert_provider = self._get_cert_provider(self.nsx_cert, self.key)
            print("Authenticating with NSX using client certificate loaded "
                  "at %s and private key loaded at %s " % (nsx_cert, key))
        if ca_cert:
            insecure = False
        else:
            print("Authenticating with NSX using basic authentication")

        nsxlib_config = config.NsxLibConfig(
            username=self.username,
            password=self.password,
            client_cert_provider=cert_provider,
            insecure=insecure,
            ca_file=self.ca_cert,
            nsx_api_managers=[self.host],
            # allow admin user to delete entities created
            # under openstack principal identity
            allow_overwrite_header=True)
        self._cluster = cluster
        self._read_only = True if read_only == "yes" else False
        self._shared_t0 = True if shared_t0 == "yes" else False
        self.nsxlib = v3.NsxLib(nsxlib_config)
        self._nsx_client = self.nsxlib.client
        self._ip_pool_client = self._get_ip_pool_client(self._nsx_client)
        self._router_port_client = self.nsxlib.logical_router_port
        self._router_client = self._get_router_client(self._nsx_client)
        self._routerlib = router.RouterLib(
            self._router_client, self._router_port_client, self.nsxlib)

    def _get_cert_provider(self, nsx_cert, key):
        cert_file = self.certpath
        data_cert_file = nsx_cert
        data_key_file = key
        if (not os.path.isfile(data_key_file) and
                not os.path.isfile(data_cert_file)):
            print("Filepaths %s and %s do not exist for PEM encoded NSX "
                  "certificate and key pair."
                  % (data_cert_file, data_key_file))
            return
        # Cert file was not created or is no longer found in filesystem
        filenames = [data_key_file, data_cert_file]
        # Create a single file from the cert and key data since NSX expects
        # one single file for certificate.
        with open(cert_file, 'w') as c_file:
            for filename in filenames:
                try:
                    with open(filename) as fname:
                        for line in fname:
                            c_file.write(line)
                except Exception as e:
                    print("Unable to write file %s to create client cert: "
                          "%s" % (filename, str(e)))
                    return
        print("Successfully created certificate file %s for NSX client "
              "connection." % cert_file)
        return client_cert.ClientCertProvider(cert_file)

    def _get_router_client(self, nsx_client):
        return resources.LogicalRouter(nsx_client)

    def _get_ip_pool_client(self, nsx_client):
        return resources.IpPool(nsx_client)

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        return self.nsxlib.logical_port.list()['results']

    def get_ncp_logical_ports(self):
        """
        Retrieve all logical ports created by NCP
        """
        lports = self.get_ncp_resources(
            self.get_logical_ports())
        return lports

    def update_logical_port_attachment(self, lports):
        """
        In order to delete logical ports, we need to detach
        the VIF attachment on the ports first.
        """
        for p in lports:
            try:
                self.nsxlib.logical_port.update(
                    p['id'], None, attachment_type=None)
            except Exception as e:
                print("ERROR: Failed to update lport %s: %s" % (p['id'], e))

    def _cleanup_logical_ports(self, lports):
        # logical port vif detachment
        self.update_logical_port_attachment(lports)
        for p in lports:
            try:
                self.nsxlib.logical_port.delete(p['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical port %s, error %s" %
                      (p['id'], e))
            else:
                print("Successfully deleted logical port %s" % p['id'])

    def cleanup_ncp_logical_ports(self):
        """
        Delete all logical ports created by NCP
        """
        ncp_lports = self.get_ncp_logical_ports()
        print("Number of NCP Logical Ports to be deleted: %s" %
              len(ncp_lports))
        if self._read_only:
            return
        self._cleanup_logical_ports(ncp_lports)

    def _is_ncp_resource(self, tags):
        correct_cluster_tag = False
        has_version_tag = False
        for tag in tags:
            if (tag.get('scope') == 'ncp/cluster' and
                    tag.get('tag') == self._cluster):
                correct_cluster_tag = True
            if tag.get('scope') == 'ncp/version':
                has_version_tag = True
        return correct_cluster_tag and has_version_tag

    def _is_ncp_cluster_resource(self, tags):
        return any(tag.get('scope') == 'ncp/cluster' and
                   tag.get('tag') == self._cluster for tag in tags)

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

    def get_ncp_cluster_resources(self, resources):
        """
        Get all logical resources with ncp/cluster tag
        """
        ncp_cluster_resources = [r for r in resources if 'tags' in r
                                 if self._is_ncp_cluster_resource(r['tags'])]
        return ncp_cluster_resources

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
        return self.nsxlib.logical_switch.list()['results']

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
                      "deleted: %s" % len(lports))
                if not self._read_only:
                    self._cleanup_logical_ports(lports)
            if self._read_only:
                continue
            try:
                self.nsxlib.logical_switch.delete(ls['id'])
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
                ip_pool = self.nsxlib.ip_pool.get(ip_pool_id)
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
                self._router_port_client.delete_by_lswitch_id(ls['id'])
            except Exception as e:
                print("Failed to delete logical router port by logical "
                      "switch %s : %s" % (ls['display_name'], e))
            else:
                print("Successfullu deleted logical router port by logical "
                      "switch %s" % ls['display_name'])

            if not subnet or not subnet_id:
                return
            all_t0_routers = self.get_logical_routers(tier='TIER0')
            if self._shared_t0:
                tier0_routers = self.get_ncp_shared_resources(all_t0_routers)
            else:
                tier0_routers = self.get_ncp_cluster_resources(all_t0_routers)
            if not tier0_routers:
                print("Error: Missing cluster tier-0 router")
                return
            if len(tier0_routers) > 1:
                print("Found %d tier-0 routers " % len(tier0_routers))
                return
            t0_id = tier0_routers[0]['id']
            print("Unconfiguring nat rules for %s from t0" % subnet)
            try:
                self.nsxlib.logical_router.delete_nat_rule_by_values(
                    t0_id, match_source_network=subnet)
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
                self.nsxlib.ip_block_subnet.delete(subnet_id)
            except Exception as e:
                print("ERROR: Failed to delete %s, error %s" %
                      (subnet, e))
            else:
                print("Successfully deleted subnet %s" % subnet)

    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        return self.nsxlib.firewall_section.list()

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
        if self._read_only:
            return
        for fw in fw_sections:
            try:
                self.nsxlib.firewall_section.delete(fw['id'])
            except Exception as e:
                print("Failed to delete firewall section %s: %s" %
                      (fw['display_name'], e))
            else:
                print("Successfully deleted firewall section %s" %
                      fw['display_name'])

    def get_ns_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        backend_groups = self.nsxlib.ns_group.list()
        ns_groups = self.get_ncp_resources(backend_groups)
        return ns_groups

    def cleanup_ncp_ns_groups(self):
        """
        Cleanup all NSGroups created by NCP
        """
        ns_groups = self.get_ns_groups()
        print("Number of NSGroups to be deleted: %s" % len(ns_groups))
        if self._read_only:
            return
        for nsg in ns_groups:
            try:
                self.nsxlib.ns_group.delete(nsg['id'])
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

    def get_ncp_ip_sets(self):
        """
        Retrieve all ip set using search API
        """
        tag = {
            'scope': self._escape_data('ncp/cluster'),
            'tag': self._escape_data(self._cluster)
        }
        try:
            ip_sets = self.nsxlib.search_by_tags(
                resource_type='IPSet', tags=[tag])
        except Exception as e:
            print("Failed to get IPSet for cluster %s: %s" %
                  (self._cluster, e))
            return []
        return ip_sets['results']

    def cleanup_ncp_ip_sets(self):
        """
        Cleanup all IP Sets created by NCP
        """
        ip_sets = self.get_ncp_ip_sets()
        print("Number of IP-Sets to be deleted: %d" % len(ip_sets))
        if self._read_only:
            return
        for ip_set in ip_sets:
            try:
                self.nsxlib.ip_set.delete(ip_set['id'])
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
        lrouters = self.nsxlib.logical_router.list(
            router_type=tier)['results']
        return lrouters

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
        return self.nsxlib.logical_router_port.get_by_router_id(lrouter['id'])

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
        if self._read_only:
            return
        for lp in lports:
            try:
                self.nsxlib.logical_router_port.delete(lp['id'])
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
        if self._read_only:
            return
        ip_pool_client = self.nsxlib.ip_pool
        try:
            ip_pool_client.release(external_pool_id, external_ip)
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
            if self._read_only:
                continue
            if lr['router_type'] == 'TIER0':
                continue
            try:
                self.nsxlib.logical_router.delete(lr['id'], force=True)
            except Exception as e:
                print("ERROR: Failed to delete logical router %s-%s, "
                      "error %s" % (lr['display_name'], lr['id'], e))
            else:
                print("Successfully deleted logical router %s-%s" %
                      (lr['display_name'], lr['id']))

    def cleanup_ncp_tier0_logical_ports(self):
        """
        Delete all TIER0 logical router ports created by NCP
        Followed the same logic in delete_project in nsxapi
        """
        tier1_routers = self.get_ncp_resources(
            self.get_logical_routers(tier='TIER1'))
        tier0_routers = self.get_ncp_shared_resources(
            self.get_logical_routers(tier='TIER0'))
        if not tier0_routers:
            print("Error: Missing cluster tier-0 router")
            return
        if len(tier0_routers) > 1:
            print("Found %d tier-0 routers " % len(tier0_routers))
            return

        t0 = tier0_routers[0]
        for t1 in tier1_routers:
            print("Router link port from %s to %s to be removed" %
                  (t0['display_name'], t1['display_name']))
            if self._read_only:
                continue
            try:
                self._routerlib.remove_router_link_port(
                    t1['id'], t0['id'])
            except Exception as e:
                print("Error removing router link port from %s to %s" %
                      (t0['display_name'], t1['display_name']), e)
            else:
                print("successfully remove link port for ",
                      t1['display_name'], t0['display_name'])

    def get_ip_pools(self):
        """
        Retrieve all ip_pools on NSX backend
        """
        return self.nsxlib.ip_pool.list()['results']

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
        ip_pool_client = self.nsxlib.ip_pool
        allocations = ip_pool_client.get_allocations(ip_pool['id'])
        if 'results' in allocations:
            for allocation in allocations['results']:
                allocated_ip = allocation['allocation_id']
                ip_pool_client.release(ip_pool['id'], allocated_ip)

        ip_pool_client.delete(ip_pool['id'])

    def cleanup_ncp_ip_pools(self):
        """
        Delete all ip pools created from NCP
        """
        ip_pools = self.get_ncp_get_ip_pools()
        print("Number of IP Pools to be deleted: %s" %
              len(ip_pools))
        if self._read_only:
            return
        for ip_pool in ip_pools:
            if 'tags' in ip_pool:
                is_external = False
                for tag in ip_pool['tags']:
                    if tag.get('scope') == 'ncp/external' \
                            and tag.get('tag') == 'true':
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
        print("Number of Loadbalance services to be delted: %s" %
              len(lb_services))
        if self._read_only:
            return
        for lb_svc in lb_services:
            try:
                self.nsxlib.load_balancer.service.delete(lb_svc['id'])
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
        return self.nsxlib.load_balancer.service.list()['results']

    def cleanup_ncp_lb_virtual_servers(self):
        lb_virtual_servers = self.get_ncp_lb_virtual_servers()
        print("Number of loadbalancer virtual servers to be delted: %s" %
              len(lb_virtual_servers))
        if self._read_only:
            return
        for lb_vs in lb_virtual_servers:
            self.release_lb_virtual_server_external_ip(lb_vs)
            try:
                self.nsxlib.load_balancer.virtual_server.delete(lb_vs['id'])
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
        ip_pool_client = self.nsxlib.ip_pool
        print("Releasing external IP %s-%s "
              "of lb virtual server %s from external pool %s" %
              (lb_vs['display_name'], lb_vs['id'],
               external_ip, external_pool_id))
        if self._read_only:
            return
        try:
            ip_pool_client.release(external_pool_id, external_ip)
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
        return self.nsxlib.load_balancer.virtual_server.list()['results']

    def cleanup_ncp_lb_rules(self):
        lb_rules = self.get_ncp_lb_rules()
        print("Number of loadbalancer rules to be delted: %s" %
              len(lb_rules))
        if self._read_only:
            return
        for lb_rule in lb_rules:
            try:
                self.nsxlib.load_balancer.rule.delete(lb_rule['id'])
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
        return self.nsxlib.load_balancer.rule.list()['results']

    def cleanup_ncp_lb_pools(self):
        lb_pools = self.get_ncp_lb_pools()
        print("Number of loadbalancer pools to be delted: %s" %
              len(lb_pools))
        if self._read_only:
            return
        for lb_pool in lb_pools:
            try:
                self.nsxlib.load_balancer.pool.delete(lb_pool['id'])
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
        return self.nsxlib.load_balancer.pool.list()['results']

    def cleanup_cert(self):
        if self.nsx_cert and self.key:
            try:
                os.close(self.fd)
                os.remove(self.certpath)
                print("Certificate file %s for NSX client connection "
                      "has been removed" % self.certpath)
            except OSError as e:
                print("Error when during cert file cleanup %s" % e)

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
        self.cleanup_ncp_tier0_logical_ports()
        self.cleanup_ncp_logical_ports()
        self.cleanup_ncp_logical_routers()
        self.cleanup_ncp_logical_switches()
        self.cleanup_ncp_ip_pools()
        self.cleanup_cert()


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username, ignored if nsx-cert is set")
    parser.add_option("-p", "--password", default="Admin!23Admin",
                      dest="password",
                      help="NSX Manager password, ignored if nsx-cert is set")
    parser.add_option("-n", "--nsx-cert", default="", dest="nsx_cert",
                      help="NSX certificate path")
    parser.add_option("-k", "--key", default="", dest="key",
                      help="NSX client private key path")
    parser.add_option("-c", "--cluster", default="kubernetes", dest="cluster",
                      help="Cluster to be removed")
    parser.add_option("-t", "--ca-cert", default="", dest="ca_cert",
                      help="NSX ca_certificate")
    parser.add_option("-r", "--read-only", default="yes", dest="read_only",
                      help="Read only mode")
    parser.add_option("-s", "--shared-t0", default="yes", dest="shared_t0",
                      help="Is T0 tagged with shared_resource or not")
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(host=options.mgr_ip,
                           username=options.username,
                           password=options.password,
                           nsx_cert=options.nsx_cert,
                           key=options.key,
                           ca_cert=options.ca_cert,
                           cluster=options.cluster,
                           read_only=options.read_only,
                           shared_t0=options.shared_t0)
    nsx_client.cleanup_all()
