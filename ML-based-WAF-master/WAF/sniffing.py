import time
from scapy.all import sniff, Raw
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
import urllib.parse
from request import Request, DBController
from classifier import ThreatClassifier
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('--port', type=int, default=5000, help='Defines which port to sniff')
args = parser.parse_args()

scapy.packet.bind_layers(TCP, HTTP, dport=args.port)
scapy.packet.bind_layers(TCP, HTTP, sport=args.port)

db = DBController()
threat_clf = ThreatClassifier()

header_fields = [
    'Http_Version', 'A_IM', 'Accept', 'Accept_Charset', 'Accept_Datetime', 'Accept_Encoding', 
    'Accept_Language', 'Access_Control_Request_Headers', 'Access_Control_Request_Method',
    'Authorization', 'Cache_Control', 'Connection', 'Content_Length', 'Content_MD5', 'Content_Type',
    'Cookie', 'DNT', 'Date', 'Expect', 'Forwarded', 'From', 'Front_End_Https', 'If_Match',
    'If_Modified_Since', 'If_None_Match', 'If_Range', 'If_Unmodified_Since', 'Keep_Alive',
    'Max_Forwards', 'Origin', 'Permanent', 'Pragma', 'Proxy_Authorization', 'Proxy_Connection',
    'Range', 'Referer', 'Save_Data', 'TE', 'Upgrade', 'Upgrade_Insecure_Requests', 'User_Agent',
    'Via', 'Warning', 'X_ATT_DeviceId', 'X_Correlation_ID', 'X_Csrf_Token', 'X_Forwarded_For',
    'X_Forwarded_Host', 'X_Forwarded_Proto', 'X_Http_Method_Override', 'X_Request_ID',
    'X_Requested_With', 'X_UIDH', 'X_Wap_Profile'
]

def get_header(packet):
    headers = {}
    for field in header_fields:
        f = getattr(packet[HTTPRequest], field, None)
        if f and f != 'None':
            headers[field] = f.decode()
    return headers

def sniffing_function(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        direction = "outbound" if src_ip.startswith(("192.168.", "10.")) else "inbound"
        print(f"Packet direction: {direction}")

    if packet.haslayer(HTTPRequest):
        req = Request()
        req.origin = packet[IP].src if packet.haslayer(IP) else 'localhost'
        req.host = urllib.parse.unquote(packet[HTTPRequest].Host.decode())
        req.request = urllib.parse.unquote(packet[HTTPRequest].Path.decode())
        req.method = packet[HTTPRequest].Method.decode()
        req.headers = get_header(packet)
        req.threat_type = 'None'

        if packet.haslayer(Raw):
            req.body = packet[Raw].load.decode()

        threat_clf.classify_request(req)
        db.save(req)

# Packet sniffing loop with 30-second interval
try:
    while True:
        sniff(prn=sniffing_function, iface='\\Device\\NPF_Loopback', filter='port ' + str(args.port), session=TCPSession, timeout=30)
        print("Waiting for 30 seconds before next capture session...")
        time.sleep(30)
finally:
    db.close()
