#!/bin/bash
#
# YACOIN - Full Mainnet Setup Script
# Run this on your VPS to set up the complete network
#

set -e

echo "==========================================="
echo "  YACOIN - FULL NETWORK SETUP"
echo "==========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
YACOIN_USER="yacoin"
YACOIN_DIR="/home/$YACOIN_USER"
DATA_DIR="/home/$YACOIN_USER/.yacoin"
RPC_USER="yacrpc"
RPC_PASS=$(openssl rand -hex 16)

echo -e "${YELLOW}Step 1: Installing dependencies...${NC}"
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake \
    pkg-config bsdmainutils python3 libssl-dev libevent-dev \
    libboost-all-dev libminiupnpc-dev libzmq3-dev libdb++-dev \
    git curl nginx certbot python3-certbot-nginx

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

echo -e "${GREEN}Dependencies installed!${NC}"
echo ""

echo -e "${YELLOW}Step 2: Building YaCoin node...${NC}"
cd $YACOIN_DIR/yacoin

# Generate build system
./autogen.sh

# Configure without GUI
./configure --without-gui --disable-tests

# Build (use all cores)
make -j$(nproc)

echo -e "${GREEN}Node built successfully!${NC}"
echo ""

echo -e "${YELLOW}Step 3: Mining genesis block...${NC}"
# Compile genesis miner
g++ -o genesis_miner src/genesis_miner.cpp -lssl -lcrypto -O3

echo "Mining genesis block (this may take a few minutes)..."
./genesis_miner | tee genesis_output.txt

# Extract values from output
GENESIS_HASH=$(grep "hashGenesisBlock" genesis_output.txt | sed 's/.*uint256S("\(.*\)").*/\1/')
GENESIS_NONCE=$(grep "nGenesisNonce" genesis_output.txt | sed 's/.*= \([0-9]*\).*/\1/')
MERKLE_ROOT=$(grep "hashGenesisMerkleRoot" genesis_output.txt | sed 's/.*uint256S("\(.*\)").*/\1/')

echo ""
echo -e "${GREEN}Genesis block mined!${NC}"
echo "Hash: $GENESIS_HASH"
echo "Nonce: $GENESIS_NONCE"
echo ""

echo -e "${YELLOW}Step 4: Updating chainparams with genesis...${NC}"
# Update chainparams.cpp with real genesis values
sed -i "s/static uint256 hashGenesisBlock = .*/static uint256 hashGenesisBlock = uint256S(\"$GENESIS_HASH\");/" src/chainparams.cpp
sed -i "s/static uint32_t nGenesisNonce = .*/static uint32_t nGenesisNonce = $GENESIS_NONCE;/" src/chainparams.cpp
sed -i "s/static uint256 hashGenesisMerkleRoot = .*/static uint256 hashGenesisMerkleRoot = uint256S(\"$MERKLE_ROOT\");/" src/chainparams.cpp

# Uncomment the assertions
sed -i 's|// assert(consensus.hashGenesisBlock|assert(consensus.hashGenesisBlock|' src/chainparams.cpp
sed -i 's|// assert(genesis.hashMerkleRoot|assert(genesis.hashMerkleRoot|' src/chainparams.cpp

echo -e "${GREEN}Chainparams updated!${NC}"
echo ""

echo -e "${YELLOW}Step 5: Rebuilding with genesis...${NC}"
make clean
make -j$(nproc)
echo -e "${GREEN}Rebuild complete!${NC}"
echo ""

echo -e "${YELLOW}Step 6: Creating configuration...${NC}"
mkdir -p $DATA_DIR

cat > $DATA_DIR/yacoin.conf << EOF
# YaCoin Configuration
# Generated $(date)

# Network
listen=1
daemon=1
server=1

# RPC
rpcuser=$RPC_USER
rpcpassword=$RPC_PASS
rpcport=9332
rpcallowip=127.0.0.1
rpcbind=127.0.0.1

# Mining
gen=0

# Connections
maxconnections=125

# Logging
debug=0
printtoconsole=0
logips=1
EOF

echo -e "${GREEN}Configuration created!${NC}"
echo "RPC User: $RPC_USER"
echo "RPC Pass: $RPC_PASS"
echo ""

echo -e "${YELLOW}Step 7: Creating systemd service...${NC}"
sudo tee /etc/systemd/system/yacoind.service > /dev/null << EOF
[Unit]
Description=YaCoin Daemon
After=network.target

[Service]
Type=forking
User=$YACOIN_USER
ExecStart=$YACOIN_DIR/yacoin/src/yacoind -daemon -conf=$DATA_DIR/yacoin.conf -datadir=$DATA_DIR
ExecStop=$YACOIN_DIR/yacoin/src/yacoin-cli stop
Restart=on-failure
RestartSec=30
TimeoutStartSec=60
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable yacoind
echo -e "${GREEN}Systemd service created!${NC}"
echo ""

echo -e "${YELLOW}Step 8: Starting node...${NC}"
sudo systemctl start yacoind
sleep 5

# Check if running
if $YACOIN_DIR/yacoin/src/yacoin-cli getblockchaininfo > /dev/null 2>&1; then
    echo -e "${GREEN}Node is running!${NC}"
else
    echo -e "${RED}Node failed to start. Check logs:${NC}"
    echo "journalctl -u yacoind -f"
fi
echo ""

echo -e "${YELLOW}Step 9: Setting up web apps...${NC}"

# Update web app configs with RPC credentials
for app in yacoin-explorer yacoin-launchpad yacoin-dex yacoin-faucet; do
    if [ -d "$YACOIN_DIR/$app" ]; then
        cat > $YACOIN_DIR/$app/.env << EOF
RPC_URL=http://127.0.0.1:9332
RPC_USER=$RPC_USER
RPC_PASS=$RPC_PASS
EOF
        cd $YACOIN_DIR/$app
        npm install --production
    fi
done

echo -e "${GREEN}Web apps configured!${NC}"
echo ""

echo -e "${YELLOW}Step 10: Creating web app services...${NC}"

# Explorer service
sudo tee /etc/systemd/system/yacoin-explorer.service > /dev/null << EOF
[Unit]
Description=YaCoin Explorer
After=yacoind.service

[Service]
Type=simple
User=$YACOIN_USER
WorkingDirectory=$YACOIN_DIR/yacoin-explorer
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
Environment=PORT=3001

[Install]
WantedBy=multi-user.target
EOF

# Launchpad service
sudo tee /etc/systemd/system/yacoin-launchpad.service > /dev/null << EOF
[Unit]
Description=YaCoin Token Launchpad
After=yacoind.service

[Service]
Type=simple
User=$YACOIN_USER
WorkingDirectory=$YACOIN_DIR/yacoin-launchpad
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
Environment=PORT=3002

[Install]
WantedBy=multi-user.target
EOF

# DEX service
sudo tee /etc/systemd/system/yacoin-dex.service > /dev/null << EOF
[Unit]
Description=YaCoin DEX
After=yacoind.service

[Service]
Type=simple
User=$YACOIN_USER
WorkingDirectory=$YACOIN_DIR/yacoin-dex
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
Environment=PORT=3003

[Install]
WantedBy=multi-user.target
EOF

# Faucet service
sudo tee /etc/systemd/system/yacoin-faucet.service > /dev/null << EOF
[Unit]
Description=YaCoin Faucet
After=yacoind.service

[Service]
Type=simple
User=$YACOIN_USER
WorkingDirectory=$YACOIN_DIR/yacoin-faucet
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
Environment=PORT=3004

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable yacoin-explorer yacoin-launchpad yacoin-dex yacoin-faucet
sudo systemctl start yacoin-explorer yacoin-launchpad yacoin-dex yacoin-faucet

echo -e "${GREEN}Web app services created and started!${NC}"
echo ""

echo -e "${YELLOW}Step 11: Setting up nginx reverse proxy...${NC}"
sudo tee /etc/nginx/sites-available/yacoin << EOF
server {
    listen 80;
    server_name _;

    # Explorer
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }

    # Launchpad
    location /launchpad {
        rewrite ^/launchpad(.*) /\$1 break;
        proxy_pass http://127.0.0.1:3002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
    }

    # DEX
    location /dex {
        rewrite ^/dex(.*) /\$1 break;
        proxy_pass http://127.0.0.1:3003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
    }

    # Faucet
    location /faucet {
        rewrite ^/faucet(.*) /\$1 break;
        proxy_pass http://127.0.0.1:3004;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/yacoin /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

echo -e "${GREEN}Nginx configured!${NC}"
echo ""

echo "==========================================="
echo -e "${GREEN}  SETUP COMPLETE!${NC}"
echo "==========================================="
echo ""
echo "Node Status:"
$YACOIN_DIR/yacoin/src/yacoin-cli getblockchaininfo 2>/dev/null || echo "Node starting up..."
echo ""
echo "Services running:"
echo "  - yacoind (blockchain node)"
echo "  - yacoin-explorer (port 3001)"
echo "  - yacoin-launchpad (port 3002)"
echo "  - yacoin-dex (port 3003)"
echo "  - yacoin-faucet (port 3004)"
echo ""
echo "Access your apps at:"
echo "  http://YOUR_VPS_IP/"
echo ""
echo "RPC Credentials (save these!):"
echo "  User: $RPC_USER"
echo "  Pass: $RPC_PASS"
echo ""
echo "Useful commands:"
echo "  yacoin-cli getblockchaininfo  - Check blockchain status"
echo "  yacoin-cli setgenerate true 1 - Start mining"
echo "  yacoin-cli getnewaddress      - Get new address"
echo "  journalctl -u yacoind -f      - View node logs"
echo ""
echo "To start mining:"
echo "  $YACOIN_DIR/yacoin/src/yacoin-cli setgenerate true 1"
echo ""
