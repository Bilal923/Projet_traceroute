# Variables
PYTHON = python
SRC = Traceroute.py
IP_FILE = ip_list.txt
PACKET_SIZE = 64
TIMEOUT = 0.1
MAX_TTL = 20
PORT = 80
NPACKETS = 3
RETRIES = 3

# Cibles 
all: run

run:
    $(PYTHON) $(SRC) $(IP_FILE) -s $(PACKET_SIZE) -t $(TIMEOUT) -m $(MAX_TTL) -p $(PORT) -n $(NPACKETS) -r $(RETRIES)

clean:
    rm -f results*.txt