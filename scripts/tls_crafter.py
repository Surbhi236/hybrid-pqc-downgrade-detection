"""
tls_crafter.py
--------------
Crafts byte-accurate TLS 1.3 ClientHello / ServerHello handshake messages
(classical, PQC-hybrid, and simulated downgrade) and wraps them in valid
TCP streams so Suricata can dissect them exactly as it would real traffic.

Key sizing choices (grounded in real-world values, referenced in the
literature and IETF drafts):
  - X25519 key_share:               32 bytes
  - Kyber768 / ML-KEM-768 pubkey:  1184 bytes  -> hybrid key_share ~1216 bytes
  - Hybrid group codepoint used:  0x11EC (X25519MLKEM768, IETF draft-ietf-tls-ecdhe-mlkem,
                                   adopted by Chrome/BoringSSL); legacy 0x6399 also supported.

We do not implement real cryptographic key exchange (not needed for IDS
signature testing) - byte lengths, extension structure and codepoints are
what matter for detection-rule evaluation.
"""

import struct
import random
from scapy.all import IP, TCP, Ether, wrpcap, Raw

# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------
TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_1_2_RECORD_VERSION = 0x0303          # record-layer version stays 1.2 for compat
TLS_1_3_VERSION = 0x0304

CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02

# Named groups
GROUP_SECP256R1 = 0x0017
GROUP_X25519 = 0x001D
GROUP_X25519_KYBER768_LEGACY = 0x6399     # Cloudflare/Chrome draft codepoint
GROUP_X25519_MLKEM768 = 0x11EC            # IETF draft-ietf-tls-ecdhe-mlkem (current, 2025/26)

# Cipher suites (TLS 1.3)
CS_AES_128_GCM_SHA256 = 0x1301
CS_AES_256_GCM_SHA384 = 0x1302
CS_CHACHA20_POLY1305_SHA256 = 0x1303

KEYSHARE_LEN = {
    GROUP_SECP256R1: 65,
    GROUP_X25519: 32,
    GROUP_X25519_KYBER768_LEGACY: 32 + 1088,   # x25519 pub + kyber768 ciphertext-ish share
    GROUP_X25519_MLKEM768: 32 + 1184,          # x25519 pub + ML-KEM-768 encaps key
}


def _ext(ext_type, payload: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(payload)) + payload


def _supported_versions_ext() -> bytes:
    versions = struct.pack("!H", TLS_1_3_VERSION)
    body = struct.pack("!B", len(versions)) + versions
    return _ext(0x002B, body)


def _supported_groups_ext(groups) -> bytes:
    glist = b"".join(struct.pack("!H", g) for g in groups)
    body = struct.pack("!H", len(glist)) + glist
    return _ext(0x000A, body)


def _key_share_ext_client(groups) -> bytes:
    entries = b""
    for g in groups:
        klen = KEYSHARE_LEN[g]
        entries += struct.pack("!HH", g, klen) + bytes(random.getrandbits(8) for _ in range(klen))
    body = struct.pack("!H", len(entries)) + entries
    return _ext(0x0033, body)


def _key_share_ext_server(group) -> bytes:
    klen = KEYSHARE_LEN[group]
    entry = struct.pack("!HH", group, klen) + bytes(random.getrandbits(8) for _ in range(klen))
    return _ext(0x0033, entry)


def _sni_ext(hostname: bytes) -> bytes:
    name_entry = struct.pack("!BH", 0x00, len(hostname)) + hostname
    body = struct.pack("!H", len(name_entry)) + name_entry
    return _ext(0x0000, body)


def build_client_hello(groups_offered, cipher_suites=None, sni=b"example-bank.com") -> bytes:
    if cipher_suites is None:
        cipher_suites = [CS_AES_128_GCM_SHA256, CS_AES_256_GCM_SHA384, CS_CHACHA20_POLY1305_SHA256]

    client_version = struct.pack("!H", 0x0303)  # legacy_version
    random_bytes = bytes(random.getrandbits(8) for _ in range(32))
    session_id = bytes(random.getrandbits(8) for _ in range(32))
    session_id_field = struct.pack("!B", len(session_id)) + session_id

    cs_list = b"".join(struct.pack("!H", c) for c in cipher_suites)
    cipher_suites_field = struct.pack("!H", len(cs_list)) + cs_list

    compression_field = struct.pack("!B", 1) + b"\x00"

    extensions = (
        _sni_ext(sni)
        + _supported_versions_ext()
        + _supported_groups_ext(groups_offered)
        + _key_share_ext_client(groups_offered)
    )
    extensions_field = struct.pack("!H", len(extensions)) + extensions

    body = (
        client_version
        + random_bytes
        + session_id_field
        + cipher_suites_field
        + compression_field
        + extensions_field
    )
    handshake = struct.pack("!B", CLIENT_HELLO) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", TLS_HANDSHAKE_CONTENT_TYPE, TLS_1_2_RECORD_VERSION, len(handshake)) + handshake
    return record


def build_change_cipher_spec() -> bytes:
    """TLS 1.3 middlebox-compatibility ChangeCipherSpec record (content type
    0x14). Real-world TLS 1.3 stacks send this right after ServerHello even
    though it carries no cryptographic meaning in 1.3. Suricata's protocol
    state machine expects to see the handshake progress past ServerHello;
    without this (and subsequent encrypted records) it treats an abruptly
    terminated flow as HANDSHAKE_INVALID_LENGTH. We include this plus a
    placeholder encrypted-looking application-data record so the flow looks
    complete to the IDS without needing a full crypto implementation.
    """
    return struct.pack("!BHH", 0x14, TLS_1_2_RECORD_VERSION, 1) + b"\x01"


def build_placeholder_encrypted_record(length=64) -> bytes:
    """Placeholder TLS record with content type 0x17 (application_data) that
    stands in for the encrypted EncryptedExtensions/Certificate/CertVerify/
    Finished sequence real TLS 1.3 servers send after ServerHello. Content is
    irrelevant (opaque ciphertext) - only the record framing matters for
    IDS stream-completeness checks."""
    payload = bytes(random.getrandbits(8) for _ in range(length))
    return struct.pack("!BHH", 0x17, TLS_1_2_RECORD_VERSION, len(payload)) + payload


def build_server_hello(chosen_group, cipher_suite=CS_AES_128_GCM_SHA256) -> bytes:
    server_version = struct.pack("!H", 0x0303)
    random_bytes = bytes(random.getrandbits(8) for _ in range(32))
    session_id = bytes(random.getrandbits(8) for _ in range(32))
    session_id_field = struct.pack("!B", len(session_id)) + session_id
    cipher_field = struct.pack("!H", cipher_suite)
    compression_field = b"\x00"

    extensions = _supported_versions_ext() + _key_share_ext_server(chosen_group)
    extensions_field = struct.pack("!H", len(extensions)) + extensions

    body = (
        server_version
        + random_bytes
        + session_id_field
        + cipher_field
        + compression_field
        + extensions_field
    )
    handshake = struct.pack("!B", SERVER_HELLO) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", TLS_HANDSHAKE_CONTENT_TYPE, TLS_1_2_RECORD_VERSION, len(handshake)) + handshake
    return record


# ---------------------------------------------------------------------------
# Packet-stream assembly (proper TCP 3-way handshake + TLS records + FIN)
# ---------------------------------------------------------------------------
def make_tcp_stream(client_ip, server_ip, sport, dport, client_payloads, server_payloads):
    """Builds a list of Ethernet/IP/TCP frames forming a valid-looking TCP
    stream: SYN, SYN-ACK, ACK, then alternating PSH/ACK data segments for
    client_payloads and server_payloads (in order), then FIN teardown."""
    pkts = []
    c_seq = random.randint(1000, 50000)
    s_seq = random.randint(1000, 50000)

    eth = Ether()

    # 3-way handshake
    syn = eth / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="S", seq=c_seq)
    pkts.append(syn)
    c_seq += 1

    synack = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, flags="SA", seq=s_seq, ack=c_seq
    )
    pkts.append(synack)
    s_seq += 1

    ack = eth / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq)
    pkts.append(ack)

    # Interleave client then server payloads (simplified: all client msgs first, then server)
    for payload in client_payloads:
        pkt = (
            eth
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=c_seq, ack=s_seq)
            / Raw(load=payload)
        )
        pkts.append(pkt)
        c_seq += len(payload)
        srv_ack = eth / IP(src=server_ip, dst=client_ip) / TCP(
            sport=dport, dport=sport, flags="A", seq=s_seq, ack=c_seq
        )
        pkts.append(srv_ack)

    for payload in server_payloads:
        pkt = (
            eth
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=dport, dport=sport, flags="PA", seq=s_seq, ack=c_seq)
            / Raw(load=payload)
        )
        pkts.append(pkt)
        s_seq += len(payload)
        cli_ack = eth / IP(src=client_ip, dst=server_ip) / TCP(
            sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq
        )
        pkts.append(cli_ack)

    # Teardown
    fin = eth / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=c_seq, ack=s_seq)
    pkts.append(fin)
    finack = eth / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, flags="FA", seq=s_seq, ack=c_seq + 1
    )
    pkts.append(finack)

    return pkts


def next_port():
    return random.randint(40000, 60000)
