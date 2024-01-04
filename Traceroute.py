import socket
import struct
import random
import time
import argparse
import matplotlib.pyplot as plt
import networkx as nx
from collections import defaultdict
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.layers.inet import TCP
from scapy.layers.inet import ICMP

# Définir une fonction pour analyser les arguments de la ligne de commande
def parse_arguments():
    parser = argparse.ArgumentParser(description='Traceroute tool')
    parser.add_argument('ip_file', metavar='IP_FILE', type=str, help='File containing list of IP addresses')
    parser.add_argument('-s', '--packet_size', metavar='PACKET_SIZE', type=int, default=64, help='Packet size (in bytes)')
    parser.add_argument('-t', '--timeout', metavar='TIMEOUT', type=float, default=0.1, help='Timeout (in seconds)')
    parser.add_argument('-m', '--max_ttl', metavar='MAX_TTL', type=int, default=20, help='Maximum time-to-live value')
    parser.add_argument('-p', '--port', metavar='PORT', type=int, default=80, help='Destination port')
    parser.add_argument('-n', '--npackets', metavar='NPACKETS', type=int, default=3, help='Number of packets per TTL')
    parser.add_argument('-r', '--retries', metavar='RETRIES', type=int, default=3, help='Number of retries')
    return parser.parse_args()


# Définir une fonction pour construire des paquets pour chaque protocole
def build_packets(dst_ip, packet_size, dst_port):
    # Créer un paquet UDP
    udp_packet = IP(dst=dst_ip, ttl=1) / UDP(dport=dst_port) / Raw(load='X'*packet_size)
    # Créer un paquet TCP
    tcp_packet = IP(dst=dst_ip, ttl=1) / TCP(dport=dst_port) / Raw(load='X'*packet_size)
    # Créer un paquet IMCP
    icmp_packet = IP(dst=dst_ip, ttl=1) / ICMP() / Raw(load='X'*packet_size)
    return udp_packet, tcp_packet, icmp_packet

# Définir une fonction pour lancer traceroute pour une adresse IP donnée
def run_traceroute(dst_ip, packet_size, dst_port, max_ttl, npackets, timeout, retries):
    ttl = 1
    nodes = {}
    # Construire des paquets pour chaque protocole
    udp_packets, tcp_packets, icmp_packets = build_packets(dst_ip, packet_size, dst_port)

   # Poursuit le traçage jusqu'à ce que le TTL maximum soit atteint ou qu'aucun nœud ne soit trouvé.
    while True:
        # Envoyer des paquets et recevoir des réponses
        responses = [sr1(packet, timeout=timeout, retry=0, verbose=0) for packet in (udp_packets, tcp_packets, icmp_packets) for i in range(npackets)]
        # Séparer les réponses par protocole
        udp_responses = responses[:npackets]
        tcp_responses = responses[npackets:npackets*2]
        icmp_responses = responses[npackets*2:]
        
        # Ajouter des nœuds au dictionnaire pour le TTL actuel
        nodes[ttl] = []
        for response in udp_responses + tcp_responses + icmp_responses:
            if response is not None:
                ip = response[IP]
                if ip.src not in nodes[ttl]:
                    nodes[ttl].append(ip.src)
                    
        # Sortir de la boucle si le TTL maximum a été atteint ou si aucun autre nœud n'est trouvé
        if ttl == max_ttl or not nodes[ttl]:
            break
        
        # Incrémenter le TTL pour la prochaine itération
        ttl += 1
        udp_packets.ttl = tcp_packets.ttl = icmp_packets.ttl = ttl

    # Retourne le dictionnaire des nœuds et leur niveau de TTL
    return nodes


# Function to write the results of the traceroute to a file
def write_results_to_file(nodes, output_file):
    with open(output_file, 'w') as f:
        for ttl, ips in nodes.items():
            f.write(f"{ttl}: ")
            f.write(", ".join([str(ip) for ip in ips]))
            f.write("\n")
            
# Fonction permettant de lire une liste d'adresses IP à partir d'un fichier
def read_ip_addresses(filename):
    with open(filename, 'r') as f:
        ips = [line.strip() for line in f]
    return ips

# Fonction permettant de tracer un graphique des résultats de traceroute
def plot_graph(nodes):
    G = nx.Graph()
    for ttl, ips in nodes.items():
        for ip in ips:
            G.add_node(ip)
            if ttl > 1:
                prev_ips = nodes[ttl-1]
                for prev_ip in prev_ips:
                    G.add_edge(ip, prev_ip)

    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, node_color='r', node_size=500)
    nx.draw_networkx_edges(G, pos, edge_color='b')
    nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')

    plt.axis('off')
    plt.show()

    
if __name__ == '__main__':
    # Analyse les arguments de la ligne de commande
    args = parse_arguments()
    # Lire les adresses IP à partir du fichier d'entrée
    ip_addresses = read_ip_addresses(args.ip_file)
    # Lancer traceroute sur chaque adresse IP et écrire les résultats dans un fichier séparé
    for ip_address in ip_addresses:
        nodes = run_traceroute(ip_address, args.packet_size, args.port, args.max_ttl, args.npackets, args.timeout, args.retries)
        write_results_to_file(nodes, f'results_{ip_address}.txt')
        # Tracer un graphique des résultats de traceroute
        plot_graph(nodes)
        
        
      