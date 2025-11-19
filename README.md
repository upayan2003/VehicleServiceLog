# Vehicle Service Log on Blockchain

A simple Streamlit app that records and verifies vehicle service history using a custom blockchain. It simulates three roles: a mechanic who logs services, an owner who confirms them, and a DMV authority that mines blocks and initializes the vehicle.

## What It Does

- Creates a blockchain with proof-of-work  
- Uses RSA keys and digital signatures for every transaction  
- Lets mechanics add service records with mileage  
- Lets owners confirm pending services  
- Shows the full chain with hashes, signatures, and metadata  
- Visualizes block links with Graphviz  

## Run the App

```bash
pip install -r requirements.txt  
streamlit run app.py
```

## Main File

- app.py – Contains blockchain implementation, transaction signing, service logic, and Streamlit UI

## Features at a Glance

- Genesis block creation
- Signed service and confirmation transactions
- Mining with automatic rewards
- Chain explorer and integrity check
- Live block graph