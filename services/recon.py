import socket
import requests

def get_ip_from_domain(domain):
    """Domain name se IP address nikalta hai."""
    try:
        # Agar user ne http:// ya https:// lagaya hai to hata dein
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        ip = socket.gethostbyname(clean_domain)
        return ip, None
    except socket.gaierror:
        return None, "Could not resolve domain. Please check the domain name."

def get_ports_and_services(ip):
    """Shodan InternetDB se open ports aur services ki details leta hai."""
    try:
        # Shodan InternetDB free API endpoint
        url = f"https://internetdb.shodan.io/{ip}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'cpes': data.get('cpes', []),
                'vulns': data.get('vulns', []),
                'tags': data.get('tags', [])
            }, None
        elif response.status_code == 404:
            return None, "No information found for this IP in Shodan database."
        else:
            return None, f"API error: {response.status_code}"
    except Exception as e:
        return None, f"Connection error: {str(e)}"

def run_network_recon(domain):
    """Domain se IP nikal kar ports aur services return karta hai."""
    ip, error = get_ip_from_domain(domain)
    if error:
        return None, error
    
    data, error = get_ports_and_services(ip)
    if error:
        return {'ip': ip, 'error': error}, None
    
    return {
        'ip': ip,
        'domain': domain,
        'ports': data['ports'],
        'hostnames': data['hostnames'],
        'cpes': data['cpes'],
        'vulns': data['vulns'],
        'tags': data['tags']
    }, None