# Wifimonitor

A Raspberry Pi WiFi monitor that passively scans and displays information about nearby WiFi networks.

## Overview

This project displays the following about nearby WiFi networks:

- **SSID & Security** -- The SSID and security type (WPA2, WPA3, WEP, Open, etc.) of all nearby WiFi networks.
- **Connected Users** -- Where possible, detect how many users are connected to each network and display this count.
- **Top DNS Domains** -- Where possible, detect the top DNS domains being requested and display a ranked chart with the number of requests for each.
- **Unencrypted Traffic Tidbits** -- On networks that are either open or where a password has been provided, display tidbits of anything unencrypted that might be interesting.

## Hardware

- **Raspberry Pi** (any model with USB support)
- **USB WiFi Dongle** -- Used to enable promiscuous/monitor mode for passive packet capture.
- **Adafruit Mini PiTFT - 135x240 Color TFT Add-on for Raspberry Pi** -- Used to show current WiFi monitor details on a compact display attached to the Pi.

## Tech

- Written in **Python**
- Runs on Raspberry Pi with a USB WiFi dongle in monitor mode
