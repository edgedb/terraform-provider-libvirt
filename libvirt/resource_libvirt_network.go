package libvirt

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	libvirt "github.com/digitalocean/go-libvirt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"libvirt.org/go/libvirtxml"
)

const (
	netModeIsolated = "none"
	netModeNat      = "nat"
	netModeRoute    = "route"
	netModeOpen     = "open"
	netModeBridge   = "bridge"
	dnsPrefix       = "dns.0"
)

// a libvirt network resource
//
// Resource example:
//
// resource "libvirt_network" "k8snet" {
//    name = "k8snet"
//    domain = "k8s.local"
//    mode = "nat"
//    addresses = ["10.17.3.0/24"]
// }
//
// "addresses" can contain (0 or 1) ipv4 and (0 or 1) ipv6 subnets
// "mode" can be one of: "nat" (default), "isolated"
//
// Not all resources support update, for those that require ForceNew
// check here: https://gitlab.com/search?utf8=%E2%9C%93&search=virNetworkDefUpdateNoSupport&group_id=130330&project_id=192693&search_code=true&repository_ref=master
//
func resourceLibvirtNetwork() *schema.Resource {
	return &schema.Resource{
		Create: resourceLibvirtNetworkCreate,
		Read:   resourceLibvirtNetworkRead,
		Delete: resourceLibvirtNetworkDelete,
		Exists: resourceLibvirtNetworkExists,
		Update: resourceLibvirtNetworkUpdate,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"domain": {
				Type:     schema.TypeString,
				Optional: true,
				// libvirt cannot update it so force new
				ForceNew: true,
			},
			"mode": { // can be "none", "nat" (default), "route", "open", "bridge"
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  netModeNat,
			},
			"bridge": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
			},
			"mtu": {
				Type:     schema.TypeInt,
				Optional: true,
				Required: false,
			},
			"addresses": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"autostart": {
				Type:     schema.TypeBool,
				Optional: true,
				Required: false,
				Computed: true,
			},
			"dns": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Required: false,
						},
						"local_only": {
							Type:     schema.TypeBool,
							Optional: true,
							Required: false,
						},
						"forwarders": {
							Type:     schema.TypeList,
							Optional: true,
							ForceNew: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"address": {
										Type:     schema.TypeString,
										Optional: true,
										Required: false,
										ForceNew: true,
									},
									"domain": {
										Type:     schema.TypeString,
										Optional: true,
										Required: false,
										ForceNew: true,
									},
								},
							},
						},
						"srvs": {
							Type:     schema.TypeList,
							Optional: true,
							ForceNew: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"service": {
										Type: schema.TypeString,
										// This should be required, but Terraform does validation too early
										// and therefore doesn't recognize that this is set when assigning from
										// a rendered dns_host template.
										Optional: true,
										ForceNew: true,
									},
									"protocol": {
										Type: schema.TypeString,
										// This should be required, but Terraform does validation too early
										// and therefore doesn't recognize that this is set when assigning from
										// a rendered dns_host template.
										Optional: true,
										ForceNew: true,
									},
									"domain": {
										Type:     schema.TypeString,
										Optional: true,
										Required: false,
										ForceNew: true,
									},
									"target": {
										Type:     schema.TypeString,
										Optional: true,
										ForceNew: true,
									},
									"port": {
										Type:     schema.TypeString,
										Optional: true,
										ForceNew: true,
									},
									"weight": {
										Type:     schema.TypeString,
										Optional: true,
										ForceNew: true,
									},
									"priority": {
										Type:     schema.TypeString,
										Optional: true,
										ForceNew: true,
									},
								},
							},
						},
						"hosts": {
							Type:     schema.TypeSet,
							ForceNew: false,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"ip": {
										Type: schema.TypeString,
										// This should be required, but Terraform does validation too early
										// and therefore doesn't recognize that this is set when assigning from
										// a rendered dns_host template.
										Optional: true,
									},
									"hostname": {
										Type: schema.TypeString,
										// This should be required, but Terraform does validation too early
										// and therefore doesn't recognize that this is set when assigning from
										// a rendered dns_host template.
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"dhcp": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				MaxItems: 1,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
							Required: false,
							Computed: true,
						},
						"range_start_offset": {
							Type:     schema.TypeInt,
							Default:  0,
							Optional: true,
							Required: false,
							ValidateFunc: func(v interface{}, k string) ([]string, []error) {
								i := v.(int)
								if i < 2 || i > 65535 {
									return nil, []error{
										fmt.Errorf("%s: must be between 2 and 65535, inclusive, got %v", k, v),
									}
								} else {
									return nil, nil
								}
							},
						},
					},
				},
			},
			"routes": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cidr": {
							Type:     schema.TypeString,
							Required: true,
						},
						"gateway": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"dnsmasq_options": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"options": {
							Type:     schema.TypeList,
							Optional: true,
							ForceNew: false,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"option_name": {
										Type: schema.TypeString,
										// This should be required, but Terraform does validation too early
										// and therefore doesn't recognize that this is set when assigning from
										// a rendered dnsmasq_options template.
										Optional: true,
									},
									"option_value": {
										Type: schema.TypeString,
										// This should be required, but Terraform does validation too early
										// and therefore doesn't recognize that this is set when assigning from
										// a rendered dnsmasq_options template.
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"xml": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"xslt": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
					},
				},
			},
		},
	}
}

func resourceLibvirtNetworkExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	virConn := meta.(*Client).libvirt
	if virConn == nil {
		return false, fmt.Errorf(LibVirtConIsNil)
	}

	uuid := parseUUID(d.Id())

	if _, err := virConn.NetworkLookupByUUID(uuid); err != nil {
		// If the network couldn't be found, don't return an error otherwise
		// Terraform won't create it again.
		if lverr, ok := err.(libvirt.Error); ok && lverr.Code == uint32(libvirt.ErrNoNetwork) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// resourceLibvirtNetworkUpdate updates dynamically some attributes in the network
func resourceLibvirtNetworkUpdate(d *schema.ResourceData, meta interface{}) error {
	// check the list of things that can be changed dynamically
	// in https://wiki.libvirt.org/page/Networking#virsh_net-update
	virConn := meta.(*Client).libvirt
	if virConn == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}

	network, err := virConn.NetworkLookupByUUID(parseUUID(d.Id()))
	if err != nil {
		return fmt.Errorf("can't retrieve network with ID '%s' during update: %s", d.Id(), err)
	}

	d.Partial(true)

	activeInt, err := virConn.NetworkIsActive(network)
	if err != nil {
		return fmt.Errorf("error when getting network %s status during update: %s", network.Name, err)
	}

	active := activeInt == 1
	if !active {
		log.Printf("[DEBUG] Activating network %s", network.Name)
		if err := virConn.NetworkCreate(network); err != nil {
			return fmt.Errorf("error when activating network %s during update: %s", network.Name, err)
		}
	}

	if d.HasChange("autostart") {
		err = virConn.NetworkSetAutostart(network, bool2int(d.Get("autostart").(bool)))
		if err != nil {
			return fmt.Errorf("error updating autostart for network %s: %s", network.Name, err)
		}
	}

	// detect changes in the DNS entries in this network
	err = updateDNSHosts(d, meta, network)
	if err != nil {
		return fmt.Errorf("error updating DNS hosts for network %s: %s", network.Name, err)
	}

	d.Partial(false)
	return nil
}

// resourceLibvirtNetworkCreate creates a libvirt network from the resource definition
func resourceLibvirtNetworkCreate(d *schema.ResourceData, meta interface{}) error {
	// see https://libvirt.org/formatnetwork.html
	virConn := meta.(*Client).libvirt
	if virConn == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}

	networkDef := newNetworkDef()
	networkDef.Name = d.Get("name").(string)
	networkDef.Domain = getDomainFromResource(d)

	// use a bridge provided by the user, or create one otherwise (libvirt will assign on automatically when empty)
	networkDef.Bridge = getBridgeFromResource(d)

	networkDef.MTU = getMTUFromResource(d)

	// check the network mode
	networkDef.Forward = &libvirtxml.NetworkForward{
		Mode: getNetModeFromResource(d),
	}
	if networkDef.Forward.Mode == netModeIsolated || networkDef.Forward.Mode == netModeNat || networkDef.Forward.Mode == netModeRoute || networkDef.Forward.Mode == netModeOpen {

		if networkDef.Forward.Mode == netModeIsolated {
			// there is no forwarding when using an isolated network
			networkDef.Forward = nil
		} else if networkDef.Forward.Mode == netModeRoute || networkDef.Forward.Mode == netModeOpen {
			// there is no NAT when using a routed or open network
			networkDef.Forward.NAT = nil
		}

		// if addresses are given set dhcp for these
		ips, err := getIPsFromResource(d)
		if err != nil {
			return fmt.Errorf("could not set DHCP from adresses '%s'", err)
		}
		networkDef.IPs = ips

		dnsEnabled, err := getDNSEnableFromResource(d)
		if err != nil {
			return err
		}

		dnsForwarders, err := getDNSForwardersFromResource(d)
		if err != nil {
			return err
		}

		dnsSRVs, err := getDNSSRVFromResource(d)
		if err != nil {
			return err
		}

		dnsHosts, err := getDNSHostsFromResource(d)
		if err != nil {
			return err
		}

		dns := libvirtxml.NetworkDNS{
			Enable:     dnsEnabled,
			Forwarders: dnsForwarders,
			Host:       dnsHosts,
			SRVs:       dnsSRVs,
		}
		networkDef.DNS = &dns

	} else if networkDef.Forward.Mode == netModeBridge {
		if networkDef.Bridge.Name == "" {
			return fmt.Errorf("'bridge' must be provided when using the bridged network mode")
		}
		networkDef.Bridge.STP = ""
	} else {
		return fmt.Errorf("unsupported network mode '%s'", networkDef.Forward.Mode)
	}

	dnsmasqOption, err := getDNSMasqOptionFromResource(d)
	if err != nil {
		return err
	}
	dnsMasqOptions := libvirtxml.NetworkDnsmasqOptions{
		Option: dnsmasqOption,
	}
	networkDef.DnsmasqOptions = &dnsMasqOptions

	// parse any static routes
	routes, err := getRoutesFromResource(d)
	if err != nil {
		return err
	}
	networkDef.Routes = routes

	// once we have the network defined, connect to libvirt and create it from the XML serialization
	log.Printf("[INFO] Creating libvirt network")

	data, err := xmlMarshallIndented(networkDef)
	if err != nil {
		return fmt.Errorf("error serializing libvirt network: %s", err)
	}
	log.Printf("[DEBUG] Generated XML for libvirt network:\n%s", data)

	data, err = transformResourceXML(data, d)
	if err != nil {
		return fmt.Errorf("error applying XSLT stylesheet: %s", err)
	}

	network, err := func() (libvirt.Network, error) {
		// define only one network at a time
		// see https://gitlab.com/libvirt/libvirt/-/issues/78
		meta.(*Client).networkMutex.Lock()
		defer meta.(*Client).networkMutex.Unlock()

		log.Printf("[DEBUG] creating libvirt network: %s", data)
		return virConn.NetworkDefineXML(data)
	}()

	if err != nil {
		return fmt.Errorf("error defining libvirt network: %s - %s", err, data)
	}

	err = virConn.NetworkCreate(network)
	if err != nil {
		// in some cases, the network creation fails but an artifact is created
		// an 'broken network". Remove the network in case of failure
		// see https://github.com/dmacvicar/terraform-provider-libvirt/issues/739
		// don't handle the error for destroying
		if err := virConn.NetworkDestroy(network); err != nil {
			log.Printf("[WARNING] %v", err)
		}

		if err := virConn.NetworkUndefine(network); err != nil {
			log.Printf("[WARNING] %v", err)
		}

		return fmt.Errorf("error creating libvirt network: %s", err)
	}
	id := uuidString(network.UUID)
	d.SetId(id)

	log.Printf("[INFO] Created network %s [%s]", networkDef.Name, d.Id())

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"BUILD"},
		Target:     []string{"ACTIVE"},
		Refresh:    waitForNetworkActive(virConn, network),
		Timeout:    1 * time.Minute,
		Delay:      5 * time.Second,
		MinTimeout: 3 * time.Second,
	}
	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("error waiting for network to reach ACTIVE state: %s", err)
	}

	if autostart, ok := d.GetOk("autostart"); ok {
		err = virConn.NetworkSetAutostart(network, bool2int(autostart.(bool)))
		if err != nil {
			return fmt.Errorf("error setting autostart for network: %s", err)
		}
	}

	return resourceLibvirtNetworkRead(d, meta)
}

// resourceLibvirtNetworkRead gets the current resource from libvirt and creates
// the corresponding `schema.ResourceData`
func resourceLibvirtNetworkRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] Read resource libvirt_network")

	virConn := meta.(*Client).libvirt
	if virConn == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}

	uuid := parseUUID(d.Id())

	network, err := virConn.NetworkLookupByUUID(uuid)
	if err != nil {
		return fmt.Errorf("error retrieving libvirt network: %s", err)
	}

	networkDef, err := getXMLNetworkDefFromLibvirt(virConn, network)
	if err != nil {
		return fmt.Errorf("error reading libvirt network XML description: %s", err)
	}

	d.Set("name", networkDef.Name)
	d.Set("bridge", networkDef.Bridge.Name)

	if networkDef.MTU != nil {
		d.Set("mtu", networkDef.MTU.Size)
	}

	if networkDef.Forward != nil {
		d.Set("mode", networkDef.Forward.Mode)
	}

	// Domain as won't be present for bridged networks
	if networkDef.Domain != nil {
		d.Set("domain", networkDef.Domain.Name)

		dnsBlock := map[string]interface{}{}
		dnsBlock["local_only"] = strings.ToLower(networkDef.Domain.LocalOnly) == "yes"
		d.Set("dns", []map[string]interface{}{dnsBlock})
	}

	autostart, err := virConn.NetworkGetAutostart(network)
	if err != nil {
		return fmt.Errorf("error reading network autostart setting: %s", err)
	}
	d.Set("autostart", autostart > 0)

	// read add the IP addresses
	addresses := []string{}
	for _, address := range networkDef.IPs {
		// we get the host interface IP (ie, 10.10.8.1) but we want the network CIDR (ie, 10.10.8.0/24)
		// so we need some transformations...
		addr := net.ParseIP(address.Address)
		if addr == nil {
			return fmt.Errorf("error parsing IP '%s': %s", address.Address, err)
		}
		bits := net.IPv6len * 8
		if addr.To4() != nil {
			bits = net.IPv4len * 8
		}

		mask := net.CIDRMask(int(address.Prefix), bits)
		network := addr.Mask(mask)
		addresses = append(addresses, fmt.Sprintf("%s/%d", network, address.Prefix))
	}
	if len(addresses) > 0 {
		d.Set("addresses", addresses)
	}

	// set as DHCP=enabled if at least one of the IPs has a DHCP configuration
	for _, address := range networkDef.IPs {
		if address.DHCP != nil {
			dhcpBlock := map[string]interface{}{}
			dhcpBlock["enabled"] = true
			offset, err := getNetworkDHCPOffset(&address)
			if err != nil {
				return fmt.Errorf("error reading network dhcp.range_start_offset: %s", err)
			}
			dhcpBlock["range_start_offset"] = offset
			d.Set("dhcp", []map[string]interface{}{dhcpBlock})
			break
		}
	}

	// read the DNS configuration
	if networkDef.DNS != nil {
		// domain settings may already had set some dns stuff
		dnsBlock := d.Get("dns.0").(map[string]interface{})

		if dnsBlock == nil {
			dnsBlock = map[string]interface{}{}
		}

		if networkDef.DNS.Enable != "" {
			dnsBlock["enabled"] = networkDef.DNS.Enable == "yes"
		}

		var forwardersBlock []map[string]interface{}
		for _, forwarder := range networkDef.DNS.Forwarders {
			forwarderBlock := map[string]interface{}{}

			if forwarder.Addr != "" {
				forwarderBlock["address"] = forwarder.Addr
			}
			if forwarder.Domain != "" {
				forwarderBlock["domain"] = forwarder.Domain
			}

			if len(forwarderBlock) > 0 {
				forwardersBlock = append(forwardersBlock, forwarderBlock)
			}
		}

		if len(forwardersBlock) > 0 {
			dnsBlock["forwarders"] = forwardersBlock
		}

		var hostsBlock []map[string]interface{}
		for _, host := range networkDef.DNS.Host {
			for _, hostName := range host.Hostnames {
				hostBlock := map[string]interface{}{}
				hostBlock["hostname"] = hostName.Hostname
				hostBlock["ip"] = host.IP
				hostsBlock = append(hostsBlock, hostBlock)
			}
		}

		if len(hostsBlock) > 0 {
			dnsBlock["hosts"] = hostsBlock
		}

		if len(dnsBlock) > 0 {
			d.Set("dns", []map[string]interface{}{dnsBlock})
		}
	}

	// and the static routes
	var routesBlock []map[string]interface{}
	for _, route := range networkDef.Routes {
		routeBlock := map[string]interface{}{}

		routeBlock["gateway"] = route.Gateway

		cidr := fmt.Sprintf("%s/%d", route.Address, route.Prefix)
		routeBlock["cidr"] = cidr

		routesBlock = append(routesBlock, routeBlock)
	}

	if len(routesBlock) > 0 {
		d.Set("routes", routesBlock)
	}

	// TODO: get any other parameters from the network and save them

	log.Printf("[DEBUG] Network ID %s successfully read", d.Id())
	return nil
}

func resourceLibvirtNetworkDelete(d *schema.ResourceData, meta interface{}) error {
	virConn := meta.(*Client).libvirt
	if virConn == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}
	log.Printf("[DEBUG] Deleting network ID %s", d.Id())

	uuid := parseUUID(d.Id())

	network, err := virConn.NetworkLookupByUUID(uuid)
	if err != nil {
		return fmt.Errorf("when destroying libvirt network: error retrieving %s", err)
	}

	activeInt, err := virConn.NetworkIsActive(network)
	if err != nil {
		return fmt.Errorf("couldn't determine if network is active: %s", err)
	}

	// network can be in 2 states, handles this case by case
	if active := int2bool(int(activeInt)); active {
		// network is active, so we need to destroy it and undefine it
		if err := virConn.NetworkDestroy(network); err != nil {
			return fmt.Errorf("when destroying libvirt network: %s", err)
		}

		if err := virConn.NetworkUndefine(network); err != nil {
			return fmt.Errorf("couldn't undefine libvirt network: %s", err)
		}
	} else {
		// in case network is inactive just undefine it
		if err := virConn.NetworkUndefine(network); err != nil {
			return fmt.Errorf("couldn't undefine libvirt network: %s", err)
		}
	}

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"ACTIVE"},
		Target:     []string{"NOT-EXISTS"},
		Refresh:    waitForNetworkDestroyed(virConn, d.Id()),
		Timeout:    1 * time.Minute,
		Delay:      5 * time.Second,
		MinTimeout: 3 * time.Second,
	}
	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("error waiting for network to reach NOT-EXISTS state: %s", err)
	}
	return nil
}
