#!/usr/bin/env python3
"""
MikroTik Wireguard Configuration Generator
=========================================
File Name: MikroTik_WG_Generator.py
Version: 1.1

A zero-dependency, highly descriptive, and persistence-capable Python script
to generate and manage MikroTik RouterOS (v7) WireGuard configurations.

Features:
- Save & Reimport configuration states as JSON (using customized filenames)
- Append new clients at a later date without rotating existing clients or server keys
- Comprehensive explanation of each option in the CLI wizard
- Pure-Python Curve25519 cryptography
"""

import os
import sys
import json
import base64
import argparse
import ipaddress

# ==============================================================================
# CRYPTOGRAPHIC ENGINE (PURE PYTHON CURVE25519 / X25519)
# ==============================================================================
P = 2**255 - 19
A24 = 121665

def field_inv(n):
    return pow(n, P - 2, P)

def x25519_scalarmult(k_int, u_int):
    x_1 = u_int
    x_2 = 1
    z_2 = 0
    x_3 = u_int
    z_3 = 1
    swap = 0
    
    for t in reversed(range(255)):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        
        A = (x_2 + z_2) % P
        AA = pow(A, 2, P)
        B = (x_2 - z_2) % P
        BB = pow(B, 2, P)
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = pow((DA + CB) % P, 2, P)
        z_3 = (x_1 * pow((DA - CB) % P, 2, P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P
        
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
        
    return (x_2 * field_inv(z_2)) % P

def clamp_private_key(private_bytes):
    a = bytearray(private_bytes)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return bytes(a)

def generate_keypair():
    raw_priv = os.urandom(32)
    clamped_priv = clamp_private_key(raw_priv)
    k_int = int.from_bytes(clamped_priv, 'little')
    pub_bytes = x25519_scalarmult(k_int, 9).to_bytes(32, 'little')
    
    private_b64 = base64.b64encode(clamped_priv).decode('utf-8')
    public_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    
    return private_b64, public_b64

# ==============================================================================
# OPTIONS HELP DICTIONARY
# ==============================================================================
OPTIONS_HELP = {
    'config_name': (
        "Configuration Name:\n"
        "Used as the filename for saving the state file (e.g. 'WireGuard_Config' becomes 'WireGuard_Config.json').\n"
        "This allows you to load this exact setup later to add more clients safely."
    ),
    'endpoint': (
        "Public Endpoint IP / Domain Name:\n"
        "The public IP address or Dynamic DNS (DDNS) host name of your MikroTik router.\n"
        "This is the address that your remote clients (phones, laptops) will use to reach your router."
    ),
    'listen_port': (
        "WireGuard Listen Port:\n"
        "The UDP port the router will listen on for VPN connections (Default: 51820).\n"
        "You must ensure this port is open in your MikroTik firewall."
    ),
    'mtu': (
        "Maximum Transmission Unit (MTU):\n"
        "Sets the packet size limit for the VPN tunnel (Default: 1420).\n"
        "Lowering the MTU prevents packet fragmentation over mobile connections."
    ),
    'interface_name': (
        "WireGuard Interface Name:\n"
        "The name of the virtual interface created on your MikroTik router (Default: wireguard1).\n"
        "This makes it easy to identify this specific tunnel in RouterOS."
    ),
    'vpn_subnet': (
        "VPN Subnet IP Range:\n"
        "The private network allocated for the VPN tunnel (Default: 10.10.0.0/24).\n"
        "Server and client IP addresses will be allocated within this range."
    ),
    'server_tunnel_ip': (
        "Router Tunnel IP:\n"
        "The router's own IP address inside the VPN subnet (Default: 10.10.0.1).\n"
        "All clients will use this IP as their primary VPN gateway."
    ),
    'enable_masquerade': (
        "NAT Masquerade:\n"
        "Enables Network Address Translation (NAT) masquerading on the router.\n"
        "If enabled, VPN clients will be able to browse the internet through the router's connection."
    ),
    'wan_interface': (
        "MikroTik WAN Interface Name:\n"
        "The interface on the router that is connected to the internet (typically ether1, combo1, or sfp-sfpplus1).\n"
        "Required for setting up the NAT masquerade rule."
    ),
    'full_tunnel': (
        "Full-Tunnel vs. Split-Tunnel:\n"
        "Full-Tunnel (Yes) routes ALL client internet and network traffic through the VPN.\n"
        "Split-Tunnel (No) only routes traffic destined for the VPN subnet and your local office LAN."
    ),
    'lan_subnet': (
        "Local LAN Subnet:\n"
        "Your home or office internal network range (e.g. 192.168.88.0/24).\n"
        "In split-tunnel mode, this allows clients to access local network printers, fileshares, or servers."
    ),
    'dns_servers': (
        "DNS Servers:\n"
        "The Domain Name System servers sent to the clients (e.g. 1.1.1.1, 8.8.8.8).\n"
        "Clients will resolve websites using these servers while connected to the VPN."
    ),
    'keepalive': (
        "Persistent Keepalive Interval:\n"
        "Sends a dummy packet every X seconds (Default: 25) to maintain the firewall connection.\n"
        "Essential for clients behind NAT (like mobile phones) to receive incoming connection traffic."
    ),
    'clients': (
        "Peers / Clients List:\n"
        "Names of clients to generate configurations for (e.g., phone, laptop).\n"
        "Separate multiple names with commas. If a state file is loaded, existing clients are preserved."
    )
}

# ==============================================================================
# PERSISTENCE & CONSTRUCT ENGINE
# ==============================================================================

def load_state(filepath):
    """Loads a previously saved JSON configuration state."""
    with open(filepath, 'r') as f:
        return json.load(f)

def save_state(filepath, params, server_keys, clients):
    """Saves the current configuration state as JSON for future re-imports."""
    state = {
        'config_name': params['config_name'],
        'endpoint': params['endpoint'],
        'listen_port': params['listen_port'],
        'mtu': params['mtu'],
        'interface_name': params['interface_name'],
        'vpn_subnet': params['vpn_subnet'],
        'server_tunnel_ip': params['server_tunnel_ip'],
        'enable_masquerade': params['enable_masquerade'],
        'wan_interface': params['wan_interface'],
        'wan_is_list': params.get('wan_is_list', False),
        'full_tunnel': params['full_tunnel'],
        'lan_subnet': params['lan_subnet'],
        'dns_servers': params['dns_servers'],
        'keepalive': params['keepalive'],
        'server_private_key': server_keys['priv'],
        'server_public_key': server_keys['pub'],
        'clients': clients
    }
    with open(filepath, 'w') as f:
        json.dump(state, f, indent=4)

def build_configs(params, existing_state=None):
    """
    Builds the configurations. If an existing_state is provided, it retains
    existing keys and clients to avoid breaking active peers.
    """
    output_dir = params['output_dir']
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Establish Server Keys
    if existing_state:
        srv_priv = existing_state['server_private_key']
        srv_pub = existing_state['server_public_key']
        print(f"--> Loaded existing Server Keys (no rotation)")
    else:
        srv_priv, srv_pub = generate_keypair()
        print(f"--> Generated new Server Keys")
        
    server_keys = {'priv': srv_priv, 'pub': srv_pub}

    # 2. Establish Network Subnets
    vpn_net = ipaddress.ip_network(params['vpn_subnet'])
    server_ip = params['server_tunnel_ip']

    # 3. Handle Client Key Pair & IP Generation (preserving existing client keys)
    clients_list = []
    
    # Track existing client IPs and keys
    existing_clients_dict = {}
    if existing_state:
        for cl in existing_state['clients']:
            existing_clients_dict[cl['name']] = cl

    current_ip = ipaddress.ip_address(server_ip) + 1

    for peer_name in params['clients']:
        # Ensure we don't overflow the subnet range
        while current_ip not in vpn_net:
            raise ValueError(f"Exceeded address limit for subnet {vpn_net}")
            
        if peer_name in existing_clients_dict:
            # Preserve existing client!
            cl = existing_clients_dict[peer_name]
            clients_list.append(cl)
            print(f"--> Preserved existing client: {peer_name} (IP: {cl['ip']})")
            # Update counter to avoid assigning this IP
            peer_ip_addr = ipaddress.ip_address(cl['ip'])
            if peer_ip_addr >= current_ip:
                current_ip = peer_ip_addr + 1
        else:
            # Generate new client!
            c_priv, c_pub = generate_keypair()
            cl = {
                'name': peer_name,
                'ip': str(current_ip),
                'private_key': c_priv,
                'public_key': c_pub
            }
            clients_list.append(cl)
            print(f"--> Generated NEW client: {peer_name} (IP: {cl['ip']})")
            current_ip += 1

    # 4. Save JSON configuration state
    state_filename = f"{params['config_name']}.json"
    state_path = os.path.join(output_dir, state_filename)
    save_state(state_path, params, server_keys, clients_list)
    print(f"--> Saved configuration state to: {state_path}")

    # 5. Generate RouterOS RSC Script
    rsc_path = os.path.join(output_dir, f"{params['config_name']}_mikrotik.rsc")
    with open(rsc_path, 'w') as f:
        f.write("# ==============================================================================\n")
        f.write("# MikroTik RouterOS v7 WireGuard Server Import Script\n")
        f.write(f"# Config Name: {params['config_name']}\n")
        f.write("# Generated automatically with zero-dependency MikroTik_WG_Generator.py\n")
        f.write("# ==============================================================================\n\n")
        
        f.write("# 1. CREATE WIREGUARD SERVER INTERFACE\n")
        f.write(f"/interface/wireguard/add name={params['interface_name']} listen-port={params['listen_port']} \\\n")
        f.write(f"    private-key=\"{srv_priv}\" mtu={params['mtu']} comment=\"WireGuard VPN Server\"\n\n")
        
        f.write("# 2. ASSIGN IP ADDRESS TO TUNNEL INTERFACE\n")
        f.write(f"/ip/address/add address={params['server_tunnel_ip']}/{vpn_net.prefixlen} \\\n")
        f.write(f"    interface={params['interface_name']} comment=\"WireGuard Tunnel Subnet\"\n\n")
        
        f.write("# 3. FIREWALL RULE: ALLOW INCOMING UDP PORT\n")
        f.write(f"/ip/firewall/filter/add action=accept chain=input comment=\"Accept WireGuard\" dst-port={params['listen_port']} protocol=udp\n\n")
        
        if params['enable_masquerade']:
            f.write("# 4. FIREWALL NAT: MASQUERADE FOR VPN CLIENTS\n")
            wan_attr = f"out-interface-list={params['wan_interface']}" if params.get('wan_is_list', False) else f"out-interface={params['wan_interface']}"
            f.write(f"/ip/firewall/nat/add chain=srcnat action=masquerade {wan_attr} \\\n")
            f.write(f"    src-address={params['vpn_subnet']} comment=\"Masquerade WireGuard VPN Traffic\"\n\n")
            
        f.write("# 5. PEERS / CLIENTS REGISTRATION\n")
        for cl in clients_list:
            f.write(f"# Client: {cl['name']} (IP: {cl['ip']})\n")
            f.write(f"/interface/wireguard/peers/add interface={params['interface_name']} \\\n")
            f.write(f"    public-key=\"{cl['public_key']}\" allowed-address={cl['ip']}/32 \\\n")
            f.write(f"    comment=\"Client: {cl['name']}\"\n\n")
            
        f.write("# ==============================================================================\n")
        f.write("# End of MikroTik script\n")
        f.write("# ==============================================================================\n")

    # 6. Generate individual client configuration files
    for cl in clients_list:
        conf_filename = f"client_{cl['name']}.conf"
        conf_path = os.path.join(output_dir, conf_filename)
        
        # Decide AllowedIPs routing
        if params['full_tunnel']:
            allowed_ips = "0.0.0.0/0, ::/0"
        else:
            route_list = [f"{cl['ip']}/32", params['vpn_subnet']]
            if params['lan_subnet']:
                route_list.append(params['lan_subnet'])
            allowed_ips = ", ".join(route_list)
            
        with open(conf_path, 'w') as f:
            f.write("# ==============================================================================\n")
            f.write(f"# WireGuard Client Configuration for: {cl['name']}\n")
            f.write(f"# Config Name: {params['config_name']}\n")
            f.write("# Import this file directly into your WireGuard client app.\n")
            f.write("# ==============================================================================\n\n")
            
            f.write("[Interface]\n")
            f.write(f"PrivateKey = {cl['private_key']}\n")
            f.write(f"Address = {cl['ip']}/{vpn_net.prefixlen}\n")
            if params['dns_servers']:
                f.write(f"DNS = {params['dns_servers']}\n")
            if params['mtu']:
                f.write(f"MTU = {params['mtu']}\n")
            f.write("\n")
            
            f.write("[Peer]\n")
            f.write(f"PublicKey = {srv_pub}\n")
            f.write(f"Endpoint = {params['endpoint']}:{params['listen_port']}\n")
            f.write(f"AllowedIPs = {allowed_ips}\n")
            if params['keepalive'] > 0:
                f.write(f"PersistentKeepalive = {params['keepalive']}\n")

    # 7. Generate instructions README
    readme_path = os.path.join(output_dir, f"{params['config_name']}_README.txt")
    with open(readme_path, 'w') as f:
        f.write("==============================================================================\n")
        f.write(f" MikroTik Wireguard Configuration: {params['config_name']}\n")
        f.write("==============================================================================\n\n")
        
        f.write("FILES CREATED IN THIS DIRECTORY:\n")
        f.write(f"1. {params['config_name']}.json         -> Configuration state file (save this to add clients later!).\n")
        f.write(f"2. {params['config_name']}_mikrotik.rsc -> Import script containing RouterOS CLI commands.\n")
        f.write("3. client_<name>.conf       -> Individual WireGuard peer configurations.\n")
        f.write(f"4. {params['config_name']}_README.txt   -> This guide.\n\n")
        
        f.write("ADD A NEW CLIENT AT A LATER DATE:\n")
        f.write("---------------------------------\n")
        f.write("To add a new client (e.g. 'new-device') without breaking existing tunnels, run:\n")
        f.write(f"  ./MikroTik_WG_Generator.py --state {state_path} --clients ")
        f.write(",".join([c['name'] for c in clients_list]) + ",new-device\n\n")
        
        f.write("HOW TO IMPORT THE SCRIPT ON MIKROTIK:\n")
        f.write("-------------------------------------\n")
        f.write(f"  1. Upload '{params['config_name']}_mikrotik.rsc' to your router via Winbox 'Files'.\n")
        f.write(f"  2. Open a Winbox terminal and type: /import file-name={params['config_name']}_mikrotik.rsc\n")
        
    return clients_list

# ==============================================================================
# INTERACTIVE CLI WIZARD
# ==============================================================================

def prompt_info(key):
    """Prints option information to make options clear to the user."""
    print(f"\n--- INFO ---")
    print(OPTIONS_HELP[key])
    print("------------")

def run_wizard():
    print("==============================================================================")
    print("       MikroTik Wireguard Configuration Generator - Setup Wizard")
    print("==============================================================================")
    print("This wizard will help you configure your WireGuard VPN with clear info.")
    print("Press Enter to select the [default values] shown in brackets.\n")

    existing_state = None
    state_path = input("Do you want to LOAD an existing saved configuration state JSON file? [y/N]:\n> ").strip().lower()
    if state_path == 'y':
        load_path = input("\nEnter the path to the state JSON file (e.g. wg-configs/WireGuard_Config.json):\n> ").strip()
        if os.path.exists(load_path):
            try:
                existing_state = load_state(load_path)
                print(f"\nSUCCESS: Loaded configuration state '{existing_state['config_name']}'!")
            except Exception as e:
                print(f"ERROR: Failed to load state file: {e}")
                sys.exit(1)
        else:
            print("ERROR: File not found. Exiting wizard.")
            sys.exit(1)

    params = {}
    
    # 1. Config Name
    if existing_state:
        default_name = existing_state['config_name']
    else:
        default_name = 'WireGuard_Config'
    prompt_info('config_name')
    name_input = input(f"Enter Configuration Name [{default_name}]:\n> ").strip()
    params['config_name'] = name_input if name_input else default_name

    # 2. Endpoint
    if existing_state:
        default_endpoint = existing_state['endpoint']
    else:
        default_endpoint = ''
    prompt_info('endpoint')
    if default_endpoint:
        endpoint_input = input(f"Enter Router Public IP / DDNS Domain [{default_endpoint}]:\n> ").strip()
        params['endpoint'] = endpoint_input if endpoint_input else default_endpoint
    else:
        endpoint = ''
        while not endpoint:
            endpoint = input("Enter Router Public IP / DDNS Domain:\n> ").strip()
            if not endpoint:
                print("ERROR: A public endpoint IP or domain is required so clients can connect!")
        params['endpoint'] = endpoint

    # 3. Port & MTU
    default_port = existing_state['listen_port'] if existing_state else 51820
    default_mtu = existing_state['mtu'] if existing_state else 1420
    
    prompt_info('listen_port')
    port_input = input(f"WireGuard UDP Port [{default_port}]:\n> ").strip()
    params['listen_port'] = int(port_input) if port_input else default_port
    
    prompt_info('mtu')
    mtu_input = input(f"Interface MTU [{default_mtu}]:\n> ").strip()
    params['mtu'] = int(mtu_input) if mtu_input else default_mtu

    # 4. Interface & Subnet
    default_iface = existing_state['interface_name'] if existing_state else 'wireguard1'
    default_subnet = existing_state['vpn_subnet'] if existing_state else '10.10.0.0/24'
    default_server_ip = existing_state['server_tunnel_ip'] if existing_state else '10.10.0.1'

    prompt_info('interface_name')
    iface_input = input(f"WireGuard Interface Name [{default_iface}]:\n> ").strip()
    params['interface_name'] = iface_input if iface_input else default_iface

    prompt_info('vpn_subnet')
    subnet_input = input(f"VPN Subnet IP Range [{default_subnet}]:\n> ").strip()
    params['vpn_subnet'] = subnet_input if subnet_input else default_subnet

    prompt_info('server_tunnel_ip')
    srv_ip_input = input(f"Router Tunnel IP inside VPN [{default_server_ip}]:\n> ").strip()
    params['server_tunnel_ip'] = srv_ip_input if srv_ip_input else default_server_ip

    # 5. NAT Masquerade
    default_masq = 'y' if (existing_state['enable_masquerade'] if existing_state else True) else 'n'
    default_wan = existing_state['wan_interface'] if existing_state else 'ether1'
    
    prompt_info('enable_masquerade')
    masq_input = input(f"Enable NAT masquerade rule? [Y/n]:\n> ").strip().lower()
    params['enable_masquerade'] = False if masq_input == 'n' else True

    if params['enable_masquerade']:
        prompt_info('wan_interface')
        wan_input = input(f"Enter MikroTik WAN Interface (or Interface List) Name [{default_wan}]:\n> ").strip()
        params['wan_interface'] = wan_input if wan_input else default_wan
        
        default_wan_list_bool = existing_state['wan_is_list'] if (existing_state and 'wan_is_list' in existing_state) else False
        default_wan_list_prompt = 'y' if default_wan_list_bool else 'n'
        wan_list_input = input(f"Is this WAN parameter a RouterOS Interface List (e.g. WAN)? [{default_wan_list_prompt}]:\n> ").strip().lower()
        params['wan_is_list'] = True if wan_list_input == 'y' else (False if wan_list_input == 'n' else default_wan_list_bool)
    else:
        params['wan_interface'] = default_wan
        params['wan_is_list'] = False

    # 6. Routing (Full / Split Tunnel)
    default_full = 'y' if (existing_state['full_tunnel'] if existing_state else True) else 'n'
    default_lan = existing_state['lan_subnet'] if existing_state else ''

    prompt_info('full_tunnel')
    route_input = input(f"Route ALL client traffic through VPN (Full Tunnel)? [Y/n]:\n> ").strip().lower()
    params['full_tunnel'] = False if route_input == 'n' else True

    if not params['full_tunnel']:
        prompt_info('lan_subnet')
        lan_input = input(f"Enter Local LAN Subnet to route in split-tunnel (e.g. 192.168.88.0/24) [{default_lan}]:\n> ").strip()
        params['lan_subnet'] = lan_input if lan_input else (default_lan if default_lan else None)
    else:
        params['lan_subnet'] = None

    # 7. DNS & Keepalive
    default_dns = existing_state['dns_servers'] if existing_state else '1.1.1.1, 8.8.8.8'
    default_ka = existing_state['keepalive'] if existing_state else 25

    prompt_info('dns_servers')
    dns_input = input(f"DNS Servers for VPN clients [{default_dns}]:\n> ").strip()
    params['dns_servers'] = dns_input if dns_input else default_dns

    prompt_info('keepalive')
    ka_input = input(f"Persistent Keepalive interval in seconds [{default_ka}]:\n> ").strip()
    params['keepalive'] = int(ka_input) if ka_input else default_ka

    # 8. Client list
    if existing_state:
        existing_names = [c['name'] for c in existing_state['clients']]
        default_clients_str = ",".join(existing_names)
    else:
        default_clients_str = 'phone,laptop'

    prompt_info('clients')
    print("Tip: To add a new client, type the existing client names plus the new client (comma-separated).")
    clients_input = input(f"Enter client names [{default_clients_str}]:\n> ").strip()
    if clients_input:
        params['clients'] = [c.strip() for c in clients_input.split(',') if c.strip()]
    else:
        params['clients'] = [c.strip() for c in default_clients_str.split(',') if c.strip()]

    params['output_dir'] = 'wg-configs'

    print("\n------------------------------------------------------------------------------")
    print("Building configurations...")
    clients_gen = build_configs(params, existing_state)
    print(f"SUCCESS! Configuration and state file saved in directory: '{params['output_dir']}/'")
    print("------------------------------------------------------------------------------\n")

# ==============================================================================
# MAIN PARSER ENTRYPOINT
# ==============================================================================

def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="MikroTik WireGuard Configuration Generator",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument("--name", default="WireGuard_Config", help="Name of the configuration / output files")
        parser.add_argument("--state", help="Path to a previously saved JSON state file to load settings and retain keys")
        parser.add_argument("--endpoint", help="Public IP or Domain name of your MikroTik Router")
        parser.add_argument("--port", type=int, default=51820, help="WireGuard UDP listen port")
        parser.add_argument("--mtu", type=int, default=1420, help="Interface MTU")
        parser.add_argument("--interface", default="wireguard1", help="WireGuard interface name on MikroTik")
        parser.add_argument("--subnet", default="10.10.0.0/24", help="VPN Subnet IP range")
        parser.add_argument("--server-ip", default="10.10.0.1", help="Router VPN Tunnel IP")
        parser.add_argument("--wan", default="ether1", help="WAN interface name for NAT Masquerade rule")
        parser.add_argument("--wan-list", action="store_true", help="Set WAN parameter as an Interface List in masquerade rule")
        parser.add_argument("--no-masquerade", action="store_true", help="Disable NAT masquerade rule generation")
        parser.add_argument("--split-tunnel", action="store_true", help="Set clients to split-tunnel mode (default: full-tunnel)")
        parser.add_argument("--lan-subnet", help="LAN Subnet to route in split-tunnel mode (e.g. 192.168.88.0/24)")
        parser.add_argument("--dns", default="1.1.1.1, 8.8.8.8", help="DNS servers assigned to clients")
        parser.add_argument("--keepalive", type=int, default=25, help="Persistent Keepalive interval in seconds")
        parser.add_argument("--clients", help="Comma-separated list of client names to generate")
        parser.add_argument("--outdir", default="wg-configs", help="Directory where files will be written")

        args = parser.parse_args()

        # Load existing state if provided
        existing_state = None
        if args.state:
            if os.path.exists(args.state):
                try:
                    existing_state = load_state(args.state)
                except Exception as e:
                    print(f"ERROR: Failed to load state: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                print(f"ERROR: State file not found at '{args.state}'", file=sys.stderr)
                sys.exit(1)

        # Merge args with existing state
        def_name = args.name if not existing_state else existing_state['config_name']
        def_endpoint = args.endpoint if args.endpoint else (existing_state['endpoint'] if existing_state else None)
        
        if not def_endpoint:
            print("ERROR: --endpoint is required when starting a new configuration.", file=sys.stderr)
            sys.exit(1)

        params = {
            'config_name': def_name,
            'endpoint': def_endpoint,
            'listen_port': args.port if not existing_state else existing_state['listen_port'],
            'mtu': args.mtu if not existing_state else existing_state['mtu'],
            'interface_name': args.interface if not existing_state else existing_state['interface_name'],
            'vpn_subnet': args.subnet if not existing_state else existing_state['vpn_subnet'],
            'server_tunnel_ip': args.server_ip if not existing_state else existing_state['server_tunnel_ip'],
            'enable_masquerade': not args.no_masquerade if not existing_state else existing_state['enable_masquerade'],
            'wan_interface': args.wan if not existing_state else existing_state['wan_interface'],
            'wan_is_list': args.wan_list if not existing_state else existing_state.get('wan_is_list', False),
            'full_tunnel': not args.split_tunnel if not existing_state else existing_state['full_tunnel'],
            'lan_subnet': args.lan_subnet if not existing_state else existing_state['lan_subnet'],
            'dns_servers': args.dns if not existing_state else existing_state['dns_servers'],
            'keepalive': args.keepalive if not existing_state else existing_state['keepalive'],
            'clients': [c.strip() for c in args.clients.split(',') if c.strip()] if args.clients else ([c['name'] for c in existing_state['clients']] if existing_state else ['client1', 'client2']),
            'output_dir': args.outdir
        }

        try:
            build_configs(params, existing_state)
            print(f"SUCCESS: Configurations successfully built in '{args.outdir}/'.")
        except Exception as e:
            print(f"ERROR: Generation failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        run_wizard()

if __name__ == '__main__':
    main()
