import socket

def is_valid_ip_addr(addr):
    is_ipv4 = is_valid_ipv4_address(addr)
    is_ipv6 = is_valid_ipv6_address(addr)

    return is_ipv4 or is_ipv6

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error: 
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  
        return False
    return True