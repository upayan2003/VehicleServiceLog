import streamlit as st
import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import graphviz
from collections import OrderedDict

# ---
# 1. BLOCKCHAIN & WALLET CLASSES
# ---

class Wallet:
    """Manages RSA keys and wallet address"""
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
    
    def get_address(self):
        """Get the public key as a string, which serves as the wallet address"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

class Transaction:
    """
    Represents a signed transaction.
    Carries service log data ('service_data', 'mileage').
    """
    def __init__(self, sender_address, recipient_address, service_data, mileage):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.service_data = service_data
        self.mileage = mileage
        self.timestamp = time.time()
        self.signature = None

    def get_payload(self):
        """Returns the data that gets signed"""
        payload = {
            "sender": self.sender_address,
            "recipient": self.recipient_address,
            "service_data": self.service_data,
            "mileage": self.mileage,
            "timestamp": self.timestamp
        }
        return json.dumps(payload, sort_keys=True).encode('utf-8')

    def sign(self, wallet):
        """Sign the transaction payload with the sender's private key"""
        if wallet.get_address() != self.sender_address:
            raise Exception("You can only sign transactions from your own wallet!")
        
        payload_bytes = self.get_payload()
        
        signature_bytes = wallet.private_key.sign(
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.signature = signature_bytes.hex()

    def to_dict(self):
        """Returns a dictionary representation of the transaction for hashing"""
        return {
            "sender": self.sender_address,
            "recipient": self.recipient_address,
            "service_data": self.service_data,
            "mileage": self.mileage,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

def verify_transaction(transaction):
    """Verifies the signature of a transaction"""
    if transaction.sender_address == "SYSTEM":
        return True # System transactions are always valid
    
    if not transaction.signature:
        st.error("Transaction has no signature to verify.")
        return False
        
    try:
        public_key = serialization.load_pem_public_key(
            transaction.sender_address.encode('utf-8')
        )
        
        payload_bytes = transaction.get_payload()
        signature_bytes = bytes.fromhex(transaction.signature)
        
        public_key.verify(
            signature_bytes,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    
    except (InvalidSignature, ValueError):
        return False

class Block:
    """A block in the blockchain, holds multiple transactions"""
    def __init__(self, index, transactions, prev_hash, timestamp=None, nonce=0):
        self.index = index
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.timestamp = timestamp if timestamp else time.time()
        self.nonce = nonce

    def hashdata(self):
        """Calculates the hash of the block"""
        tx_payload = json.dumps([tx.to_dict() for tx in self.transactions], sort_keys=True)
        block_string = str(self.index) + tx_payload + self.prev_hash + str(self.timestamp) + str(self.nonce)
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

class Blockchain:
    """Manages the chain of blocks and mining"""
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = 4

    def create_genesis_block(self):
        """Creates the very first block (Block 0)"""
        return Block(index=0, transactions=[], prev_hash="0", timestamp=time.time())

    def get_last_block(self):
        """Returns the last block in the chain"""
        return self.chain[-1]

    def add_transaction(self, transaction):
        """Adds a verified transaction to the pending pool"""
        if not transaction.sender_address or not transaction.recipient_address:
            st.error("Transaction must include a sender and recipient")
            return False
        if not verify_transaction(transaction):
            st.error("Cannot add invalid transaction")
            return False
        
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self, miner_address):
        """Mines a new block with all pending transactions"""
        if not self.pending_transactions:
            st.info("No pending transactions to mine.")
            return False

        reward_tx = Transaction(
            sender_address="SYSTEM", 
            recipient_address=miner_address, 
            service_data="Mining Reward", 
            mileage=0
        )
        
        block_transactions = self.pending_transactions + [reward_tx]
        
        new_block = Block(
            index=len(self.chain),
            transactions=block_transactions,
            prev_hash=self.get_last_block().hashdata()
        )

        target = '0' * self.difficulty
        while new_block.hashdata()[:self.difficulty] != target:
            new_block.nonce += 1
        
        self.chain.append(new_block)
        self.pending_transactions = []
        return True

def is_valid_chain(chain):
    """Validates the entire blockchain"""
    for i, block in enumerate(chain):
        # We access difficulty from the block's parent blockchain object if possible,
        # but for this app, we'll hardcode the check.
        if block.hashdata()[:4] != '0000':
            st.error(f"Block {i} hash is invalid (Proof of Work failed).")
            return False
        
        if i > 0 and block.prev_hash != chain[i-1].hashdata():
            st.error(f"Invalid hash linkage at block {i}.")
            return False
    
    st.success("Chain is valid!")
    return True

# ---
# 2. NEW HELPER FUNCTION FOR SERVICE VALIDATION
# ---

def get_unconfirmed_services(blockchain, mechanic_address, owner_address):
    """
    Scans the blockchain to find services logged by the mechanic
    that have not yet been confirmed by the owner.
    """
    # Use OrderedDict to remember the mileage (value) for each service (key)
    all_services = OrderedDict()
    confirmed_services = set()
    
    for block in blockchain.chain:
        for tx in block.transactions:
            
            # Log all services added by the mechanic
            if tx.sender_address == mechanic_address:
                all_services[tx.service_data] = tx.mileage
                
            # Log all confirmations by the owner
            elif tx.sender_address == owner_address and tx.service_data.startswith("CONFIRMED:"):
                # Extract the original service name
                original_service = tx.service_data.replace("CONFIRMED: ", "")
                confirmed_services.add(original_service)

    # Find which services are in 'all_services' but not in 'confirmed_services'
    unconfirmed = OrderedDict()
    for service, mileage in all_services.items():
        if service not in confirmed_services:
            unconfirmed[service] = mileage
            
    return unconfirmed

# ---
# 3. STREAMLIT APPLICATION UI
# ---

st.set_page_config(layout="wide", page_title="Vehicle Service Log")
st.title("⛓️ Vehicle Service Log on a Blockchain")

# ---
# 4. INITIALIZATION & SESSION STATE
# ---

if 'blockchain' not in st.session_state:
    st.session_state.blockchain = Blockchain()
    st.session_state.wallets = {
        "DMV": Wallet(),
        "Mechanic_Shop": Wallet(),
        "Car_Owner": Wallet()
    }
    
    st.info("Initializing blockchain... Minting vehicle (VIN: 12345ABC)...")
    
    wallet_dmv = st.session_state.wallets["DMV"]
    addr_dmv = wallet_dmv.get_address()
    addr_owner = st.session_state.wallets["Car_Owner"].get_address()

    mint_tx = Transaction(
        sender_address=addr_dmv,
        recipient_address=addr_owner,
        service_data="Vehicle 'Minted' (VIN: 12345ABC)",
        mileage=1
    )
    mint_tx.sign(wallet_dmv)
    st.session_state.blockchain.add_transaction(mint_tx)
    st.session_state.blockchain.mine_pending_transactions(addr_dmv)
    st.success("Vehicle Minted! Blockchain is live.")


# Get the latest objects from session state
blockchain = st.session_state.blockchain
wallets = st.session_state.wallets
addr_mechanic = wallets["Mechanic_Shop"].get_address()
addr_owner = wallets["Car_Owner"].get_address()
addr_dmv = wallets["DMV"].get_address()

# ---
# 5. DEFINE UI TABS
# ---

tab1, tab2, tab3, tab4 = st.tabs([
    "Add Service Record (Mechanic)", 
    "Confirm Service Done (Owner)",  # <-- NEW TAB
    "View Full Chain", 
    "Visualize Chain Structure"
])


# --- TAB 1: Add Service Record (Mechanic's View) ---
with tab1:
    st.header("Add a New Service Record")
    st.markdown(f"**Signing As:** `Mechanic_Shop`")
    st.markdown(f"**Recipient:** `Car_Owner`")
    
    with st.form("service_form"):
        service_details = st.text_input("Service Performed (e.g., 'Oil Change', 'Tire Rotation')")
        mileage = st.number_input("Current Vehicle Mileage", min_value=1, step=1)
        
        submit_button = st.form_submit_button("Add and Mine Service Record")

    if submit_button:
        if not service_details or mileage <= 0:
            st.warning("Please fill out all fields.")
        else:
            with st.spinner("Creating and signing transaction..."):
                tx = Transaction(
                    sender_address=addr_mechanic,
                    recipient_address=addr_owner,
                    service_data=service_details,
                    mileage=int(mileage)
                )
                tx.sign(wallets["Mechanic_Shop"])
                blockchain.add_transaction(tx)
                st.success("Transaction signed and added to pending pool.")
            
            with st.spinner(f"Mining block {len(blockchain.chain)}..."):
                success = blockchain.mine_pending_transactions(addr_dmv) # DMV acts as miner
                if success:
                    st.success(f"Block {len(blockchain.chain)-1} Mined Successfully!")
                    st.toast('New service record added!', icon='🔧')
                else:
                    st.error("Mining failed.")

# --- TAB 2: Confirm Service Done (Owner's View) ---
with tab2:
    st.header("Confirm a Completed Service")
    st.markdown(f"**Signing As:** `Car_Owner`")
    st.markdown("Here you can cryptographically sign-off on services performed by the mechanic.")
    
    # Find all unconfirmed services
    unconfirmed_services = get_unconfirmed_services(blockchain, addr_mechanic, addr_owner)
    
    if not unconfirmed_services:
        st.success("All recorded services have been confirmed!")
    else:
        st.warning("The following services are awaiting your confirmation:")
        
        with st.form("confirm_form"):
            # Create a list of options for the selectbox
            options = list(unconfirmed_services.keys())
            
            selected_service = st.selectbox(
                "Select service to confirm", 
                options=options,
                format_func=lambda x: f"{x} (at {unconfirmed_services[x]} miles)"
            )
            
            confirm_button = st.form_submit_button("Confirm Service (Sign with Digital Signature)")

        if confirm_button:
            if selected_service:
                with st.spinner("Creating and signing confirmation transaction..."):
                    # Get the mileage from the service we are confirming
                    mileage_at_service = unconfirmed_services[selected_service]
                    
                    # Create the new confirmation transaction
                    tx = Transaction(
                        sender_address=addr_owner, # From Owner
                        recipient_address=addr_mechanic, # To Mechanic (as a receipt)
                        service_data=f"CONFIRMED: {selected_service}",
                        mileage=int(mileage_at_service) # Log the same mileage
                    )
                    
                    tx.sign(wallets["Car_Owner"]) # Sign with Owner's key
                    blockchain.add_transaction(tx)
                    st.success("Confirmation transaction signed and added to pool.")
                
                with st.spinner(f"Mining block {len(blockchain.chain)}..."):
                    success = blockchain.mine_pending_transactions(addr_dmv)
                    if success:
                        st.success(f"Block {len(blockchain.chain)-1} Mined Successfully!")
                        st.toast('Service confirmed!', icon='🎉')
                    else:
                        st.error("Mining failed.")
            else:
                st.error("No service selected to confirm.")


# --- TAB 3: View Full Chain ---
with tab3:
    st.header("Complete Vehicle History (Immutable Log)")
    
    if st.checkbox("Validate Chain Integrity"):
        is_valid_chain(blockchain.chain)

    st.write(f"**Current Chain Length:** {len(blockchain.chain)} blocks")
    
    # Display blocks in reverse order (newest first)
    for block in reversed(blockchain.chain):
        st.write("---")
        with st.expander(f"Block #{block.index} (Timestamp: {time.ctime(block.timestamp)})"):
            st.markdown(f"**Hash:** `{block.hashdata()}`")
            st.markdown(f"**Previous Hash:** `{block.prev_hash}`")
            st.markdown(f"**Nonce (Proof-of-Work):** `{block.nonce}`")
            
            st.subheader("Transactions in this block:")
            for tx in block.transactions:
                # Prettify sender/recipient names for display
                sender_name = next((name for name, wallet in wallets.items() if wallet.get_address() == tx.sender_address), "SYSTEM")
                recipient_name = next((name for name, wallet in wallets.items() if wallet.get_address() == tx.recipient_address), "Unknown")

                # --- NEW: Improved Transaction Display ---
                if sender_name == "Mechanic_Shop":
                    st.markdown(f"**Service Record:** `{tx.service_data}`")
                elif sender_name == "Car_Owner":
                    st.markdown(f"**Owner Confirmation:** `{tx.service_data}`")
                elif sender_name == "DMV":
                    st.markdown(f"**Vehicle Minted:** `{tx.service_data}`")
                elif sender_name == "SYSTEM":
                    st.markdown(f"**Mining Reward:** `{tx.service_data}`")
                
                st.markdown(f"**Mileage:** `{tx.mileage}`")
                st.markdown(f"**From:** `{sender_name}`")
                st.markdown(f"**To:** `{recipient_name}`")
                
                is_valid = verify_transaction(tx)
                st.markdown(f"**Signature Valid:** {':white_check_mark:' if is_valid else ':x:'}")
                
                # Handle SYSTEM transactions with no signature
                st.code(f"Signature: {tx.signature[:40]}..." if tx.signature else "Signature: N/A (SYSTEM Transaction)", language=None)
                st.write("---")


# --- TAB 4: Visualize Chain Structure ---
with tab4:
    st.header("Live Blockchain Visualization")
    st.markdown("This graph shows the immutable links between blocks.")

    dot = graphviz.Digraph(comment='Blockchain')
    dot.attr(rankdir='LR') 
    dot.attr('node', shape='box', style='filled', color='skyblue')

    for i, block in enumerate(blockchain.chain):
        block_hash = block.hashdata()
        label = f"Block {block.index}\nHash: {block_hash[:10]}...\nNonce: {block.nonce}"
        dot.node(f'block_{i}', label)
        
        if i > 0:
            dot.edge(f'block_{i-1}', f'block_{i}', label=f"prev_hash:\n{block.prev_hash[:10]}...")

    st.graphviz_chart(dot)