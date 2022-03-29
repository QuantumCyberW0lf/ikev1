from scapy.all import *
import binascii

"""
Define some constants because of the annoying unittest in main
"""

ISAKMP_KEX_NAME = ISAKMP_payload_KE
ISAKMP_NONCE_NAME = ISAKMP_payload_Nonce

def getIniatorSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    #TODO Get frist initiator SA ISAKMP layer
    for p in packets:
        if p.haslayer(ISAKMP):
            if binascii.hexlify(bytes(p[ISAKMP].resp_cookie))==b'0'*16:
                return p


def getResponderSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    #TODO Get first responder SA ISAKMP layer
    for p in packets:
        if p.haslayer(ISAKMP):
            if binascii.hexlify(bytes(p[ISAKMP].resp_cookie))!=b'0'*16:
                return p


def getPayloadFromISAKMP(packet: scapy.layers.isakmp.ISAKMP, name: str) -> bytes:
    # name == payload name
    # TODO Get the corresponding load from the selected (by name) layer
    if packet.haslayer(name):
        return packet[name].load

def getCookieFromISAKMP(respPacket: scapy.layers.isakmp.ISAKMP, responderCookie: bool) -> bytes:
    # TODO return corresponding cookie value
    # true -> responder cookie
    # false -> initiator cookie
    if(responderCookie):
        return getResponderSAPacket(respPacket).resp_cookie
    else:
        for p in respPacket:
            if p.haslayer(ISAKMP):
                return p[ISAKMP].init_cookie

def getSAPayloadFromInitPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Get the SA payload only from initiator packet
    init_packet = getIniatorSAPacket(packet)
    SA_res_raw = raw(init_packet[ISAKMP_payload_SA].prop)
    data = [b'\x00\x00\x00\x01',b'\x00\x00\x00\x01',SA_res_raw]
    result = b''.join(data)
    return result
    

def getResponderIDFromRespPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Return responder ID from ISAKMP layer 
    # Responder ID consist of  IDType||ProtoID||Port||load
    resp_packet = getResponderSAPacket(packet)
    data = [b'\x01',b'\x00',b'\x00\x00',resp_packet[ISAKMP_payload_ID].load]
    id_r = b''.join(data)
    return id_r
    

def getRespHashfromPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Get the hash value to compare your computed value against
    resp_packet = getResponderSAPacket(packet)
    return resp_packet[ISAKMP_payload_Hash].load
