
import socket
import time
import re
import hashlib
import random
import string
import base64
import datetime
import struct

class UdpClient:
    """ Helios IP UDP service client
    """
    
    MULTICAST_ADDR = "235.255.255.239"

    def __init__(self):
        """ Initializes udp client instance
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', 0))
        mreq = struct.pack("4sl", socket.inet_aton(self.MULTICAST_ADDR), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.sock.close()
        pass

    def setnonblocking(self):
        """Sets udp client receive to non blocking mode
        """
        self.sock.setblocking(False)


    def settimeout(self, timeout):
        """Sets udp client receive timeout
        timeout --- timeout in seconds
        """
        self.sock.settimeout(timeout)


    def build_message(self, headers):
        req_string = 'hip/1.0\r\n'
        # build request headers 
        for pair in headers:
            req_string += pair[0] + ': ' + pair[1] + '\r\n'
        # encode utf-8 string 
        return req_string.encode()        

    def send_request(self, ipaddress, headers):
        """Sends request to ipaddress
        headers -- array of request headers [ ('param-name', 'param-value'), ... ]
        """
        # build first request line
        # send request
        self.sock.sendto(self.build_message(headers), 0, (ipaddress, 8002))

    def _parse_response_headers(self, rsp_string):
        """Parses response string into dictionary of response parameters
        rsp -- response string
        Returns response headers [ ('param-name', 'param-value'), ... ]
        """
        lines = rsp_string.splitlines()
        # first line must contain hip/1.0
        if (len(lines) > 0) and (lines[0] == "hip/1.0"):
            headers = []
            for line in lines[1:]:
                # each line contains pair param-name:param-value
                match = re.match('(.*?):\s*(.*)\s*', line)
                if match != None:
                    headers.append((match.group(1), match.group(2)))
            return headers

    
    def receive_response(self):
        """Receives response
        Returns tuple (headers, ipaddress)
        """
        try:
            rsp_bytes, addr = self.sock.recvfrom(1500)
            ipaddr, port = addr
            # decode utf-8 string
            rsp_string = rsp_bytes.decode()
            # parse response parameters
            headers = self._parse_response_headers(rsp_string)
            return (headers, ipaddr)
        except ConnectionResetError:
            # nobody is listening
            return (None, None)
        except socket.timeout:
            # no response in blocking mode 
            return (None, None)
        except BlockingIOError:
            # no response in non-blocking mode
            return (None, None)
        except:
            return (None, None)



def scan_network(wait=2, hip_sn=None):
    """ Scans local network for Helios IP devices
    returns list of devices 
    """
    
    # dictionary of found devices
    assert wait >= 0.3
    t_sleep = 0.1
    devices = {}
    total_ticks = int(wait/t_sleep)
    
    with UdpClient() as client:
        client.setnonblocking()
        # send request and process responses from all devices
        for _ in range(1, total_ticks):

            client.send_request('<broadcast>', [('request', 'echo')] )
            client.send_request('<broadcast>', [('request', 'x-discover')] )
            client.send_request(client.MULTICAST_ADDR, [('request', 'x-discover')] )

            response, ipaddr = client.receive_response()
            while response is not None:
                # add own ip-addr parameter
                response.append(('ip-addr', ipaddr))
                response = dict(response)
                if hip_sn == response["serial-number"]:
                    return response
                # save device response
                if not hip_sn:
                    devices[ipaddr] = response
                # try to read next response
                response, ipaddr = client.receive_response()
            # next tick after 100ms
            time.sleep(t_sleep)

    return [response for response in devices.values()]
    

def send_request(ipaddress, headers):
    """ Send message to hip udp_server and returns response
    ipaddress - device ip address
    headers - array of request headers [('param-name', 'param-value'), ...]
    returns response headers 
    returns None if not response is received in 500ms
    """
    with UdpClient() as client:
        # set receive timeout
        client.settimeout(0.5)
        # send request
        client.send_request(ipaddress, headers)
        # return first response or None
        return client.receive_response()


def send_echo(ipaddress):
    """ Send echo message to hip
    ipaddress - device ip address
    returns dictonary of response headers {'param-name': 'param-value', ...}
    returns None if not response is received in 500ms
    """
    response, ipaddr = send_request(ipaddress, [('request', 'echo')])
    
    if response is not None:
        response.append(('ip-addr', ipaddr))
        return dict(response)
    else:
        return None

def send_discover(ipaddress):
    """ Send echo message to hip
    ipaddress - device ip address
    returns dictonary of response headers {'param-name': 'param-value', ...}
    returns None if not response is received in 500ms
    """
    response, ipaddr = send_request(ipaddress, [('request', 'x-discover')])
    
    if response is not None:
        response.append(('ip-addr', ipaddr))
        return dict(response)
    else:
        return None

def find_device(serial_number):
    """ Searches for device with specific serial number
    returns dictonary of response headers {'param-name': 'param-value', ...}
    returns None if device is not found
    """
    devinfo = scan_network(hip_sn=serial_number)
    if devinfo:
        return devinfo
    return None

def send_multicast_trigger(command, params=None, password="", fake_time=False):
    nonce_data = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    nonce_hash = base64.b64encode(hashlib.sha1(nonce_data.encode()).digest()).decode("utf-8")
    timestamp = datetime.datetime.utcnow()
    if fake_time:
        timestamp = timestamp.replace(hour=timestamp.hour-2)
    created = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = hashlib.sha1()
    digest.update(base64.b64decode(nonce_hash.encode()))
    digest.update(created.encode())
    digest.update(password.encode())
    digest = base64.b64encode(digest.digest()).decode("utf-8")
    data = '''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
    xmlns:aut="http://www.2n.cz/automation">
    <s:Body>
        <aut:MulticastRequest>
            <aut:Command>{}</aut:Command>
            <aut:Nonce>{}</aut:Nonce>
            <aut:Created>{}</aut:Created>
            <aut:Digest>{}</aut:Digest>
        </aut:MulticastRequest>
    </s:Body>
</s:Envelope>'''.format(command, nonce_hash, created, digest)
    if params != None:
        params_elem = "<aut:Params>{}</aut:Params>\n".format(params.replace(",", "&amp;"))
        index = data.find("</aut:Command>")
        data = data[:index + 15] + params_elem + data[index + 15:]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    for _ in range(5):
        sock.sendto(data.encode(),("235.255.255.250", 4433))

def send_config(serial_number, mac_address, device_password, headers=[("dhcp-enabled", "1")]):
    with UdpClient() as client:
        seq = int(time.time())
        headers = [('request', "x-config"), ("seq", str(seq)), ("mac-address", mac_address) , ("serial-number", serial_number)] + headers 
        # set receive timeout
        client.settimeout(2)
        # send request
        client.send_request(client.MULTICAST_ADDR, headers)
        # return first response or None
        challenge = dict(client.receive_response()[0])["challenge"]
        
        headers[1] = ("seq", str(seq+1))
        mess = client.build_message(headers)
        mess += b"auth: " + base64.b64encode(hashlib.sha1(base64.b64encode(hashlib.sha1(device_password.encode()).digest()) + challenge.encode() + mess).digest())
        
        client.sock.sendto(mess, 0, (client.MULTICAST_ADDR, 8002))
        
        assert dict(client.receive_response()[0])["status"] == "200 OK"
        