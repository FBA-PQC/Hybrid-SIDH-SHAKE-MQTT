# Hybrid SIDH-SHAKE Masking over MQTT

## Overview

This project implements a lightweight masking scheme for isogeny-based public keys using:

- SIDH/SIKE P434 for public key generation
- SHAKE-256 for masking public keys before transmission
- MQTT (Mosquitto) for communication between Alice and Bob

The main idea is to avoid sending raw SIDH public keys over the network.  
Instead, each public key is masked with a keystream derived from:

- a shared static bootstrap seed
- a fresh nonce
- a direction-dependent context string

This helps hide the structure of the transmitted public key.

---

1) Build the SIKE library first

cd $HOME/PQCrypto-SIDH
make clean
make lib434 ARCH=ARM64 CC=gcc OPT_LEVEL=GENERIC

2) Check that the library exists:

ls $HOME/PQCrypto-SIDH/lib434/libsidh.a

3) And check the headers:

ls $HOME/PQCrypto-SIDH/src/P434

4) run 
cd /home/replace it with pi username/Desktop/Hybrid-SIDH-SHAKE-MQTT
rm -rf build
mkdir build && cd build
cmake -DUSE_PQSIDH=ON -DSIDH_ROOT=$HOME/PQCrypto-SIDH ..
make -j

## Masking construction


# =========================
# 1) Start Mosquitto broker
# =========================

# On the chosen broker machine:
sudo systemctl enable --now mosquitto

# Or run manually:
# mosquitto -v


# =========================
# 2) Important: same static seed on both sides
# =========================

# Alice and Bob must use the SAME bootstrap seed
# in their source code, for example in:
#   src/alice_mqtt.c
#   src/bob_mqtt.c
#
# The masking key stream is now derived directly from:
#   BOOTSTRAP_SEED + nonce + context


# =========================
# 3) Run Bob first
# =========================

cd build
./bob_mqtt


# =========================
# 4) Run Alice
# =========================

cd build
./alice_mqtt
