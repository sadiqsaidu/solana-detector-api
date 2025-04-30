"""
Solana Dust & Address Poisoning Detection API

This FastAPI application provides endpoints to detect dusting attacks
and address poisoning attempts on the Solana blockchain.

MIT License

Copyright (c) 2025 Solana Dust Detection Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import json
import asyncio
import datetime
import logging
import Levenshtein
from typing import List, Dict, Optional, Union, Any
from collections import defaultdict
from functools import lru_cache

import httpx
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="Solana Dust & Address Poisoning Detection API",
    description="API for detecting SOL dusting attacks and address poisoning attempts",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Modify in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Environment variables
HELIUS_API_KEY = os.getenv("HELIUS_API_KEY", "")
SOLANA_RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")

# Constants for detection
DUST_THRESHOLD = 0.001  # Maximum SOL amount for dust (0.001 SOL = 1,000,000 lamports)
MIN_DUST_THRESHOLD = 0.000001  # Minimum SOL amount to consider (to filter out noise)
DUST_TIME_WINDOW = 30  # Days to look back for dusting patterns
DUST_SENDER_THRESHOLD = 5  # Number of dust txs sent to be considered suspicious
DUST_VICTIM_THRESHOLD = 3  # Number of distinct victims for a sender to be suspicious
ADDRESS_PREFIX_LENGTH = 4  # Characters to check for address prefix matching
LEVENSHTEIN_THRESHOLD = 3  # Maximum edit distance for addresses to be considered similar
CACHE_EXPIRY = 3600  # Cache expiry in seconds (1 hour)

# -------------------- Data Models --------------------

class SolanaAddress(BaseModel):
    """Solana public key / address."""
    address: str
    
    @validator('address')
    def validate_solana_address(cls, v):
        if not v or not isinstance(v, str) or len(v) != 44 or not v.startswith(('1', '2', '3', '4', '5', '6', '7', '8', '9')):
            raise ValueError('Invalid Solana address format')
        return v

class TransactionSignature(BaseModel):
    """Solana transaction signature."""
    signature: str
    
    @validator('signature')
    def validate_tx_signature(cls, v):
        if not v or not isinstance(v, str) or len(v) < 32:
            raise ValueError('Invalid Solana transaction signature format')
        return v

class AddressAnalysisRequest(BaseModel):
    """Request for analyzing a single address."""
    address: str
    time_window_days: Optional[int] = Field(default=DUST_TIME_WINDOW, ge=1, le=365)
    include_transactions: Optional[bool] = Field(default=False)

class MultiAddressAnalysisRequest(BaseModel):
    """Request for analyzing multiple addresses."""
    addresses: List[str]
    time_window_days: Optional[int] = Field(default=DUST_TIME_WINDOW, ge=1, le=365)
    include_transactions: Optional[bool] = Field(default=False)

class TransactionAnalysisRequest(BaseModel):
    """Request for analyzing a set of transaction signatures."""
    signatures: List[str]
    include_details: Optional[bool] = Field(default=True)

class DustingResult(BaseModel):
    """Results of dusting analysis."""
    is_dusting: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    dust_received_count: int = 0
    dust_sent_count: int = 0
    unique_dust_senders: int = 0
    total_dust_amount: float = 0.0
    first_dust_date: Optional[str] = None
    last_dust_date: Optional[str] = None
    transactions: Optional[List[Dict[str, Any]]] = None

class PoisoningResult(BaseModel):
    """Results of address poisoning analysis."""
    is_poisoning: bool
    confidence_score: float = Field(ge=0.0, le=1.0)
    similar_addresses: List[Dict[str, Any]] = []
    prefix_matches: List[Dict[str, Any]] = []
    transactions: Optional[List[Dict[str, Any]]] = None

class AddressAnalysisResponse(BaseModel):
    """Full response for an address analysis."""
    address: str
    label: str = Field(description="One of: 'dusting', 'address_poisoning', 'both', 'benign'")
    dusting: DustingResult
    poisoning: PoisoningResult
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

class TransactionAnalysisResponse(BaseModel):
    """Response for transaction analysis."""
    signature: str
    is_dust: bool
    is_poisoning: bool
    label: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    details: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

# -------------------- Helper Functions --------------------

async def get_client():
    """Get HTTPX client with timeout."""
    return httpx.AsyncClient(timeout=30.0)

async def get_solana_balance(address: str, client: httpx.AsyncClient) -> float:
    """Get SOL balance for an address."""
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [address]
        }
        response = await client.post(SOLANA_RPC_URL, json=payload)
        data = response.json()
        
        if "result" in data and "value" in data["result"]:
            # Convert lamports to SOL
            return data["result"]["value"] / 1_000_000_000
        else:
            logger.error(f"Failed to get balance: {data}")
            return 0.0
    except Exception as e:
        logger.error(f"Error getting balance for {address}: {str(e)}")
        return 0.0

async def get_account_transactions(
    address: str, 
    time_window_days: int = DUST_TIME_WINDOW,
    client: httpx.AsyncClient = None
) -> List[Dict[str, Any]]:
    """Get transactions for a Solana address using Helius API."""
    if not client:
        client = await get_client()
    
    if not HELIUS_API_KEY:
        # Fallback to regular RPC if no Helius API key
        return await get_account_transactions_rpc(address, time_window_days, client)
    
    try:
        # Use Helius API for enhanced transaction data
        url = f"https://api.helius.xyz/v0/addresses/{address}/transactions"
        
        # Calculate timestamp for time window
        current_time = datetime.datetime.utcnow()
        start_time = current_time - datetime.timedelta(days=time_window_days)
        start_timestamp = int(start_time.timestamp())
        
        params = {
            "api-key": HELIUS_API_KEY,
            "type": "SOL_TRANSFER",  # Focus on SOL transfers
            "before": int(current_time.timestamp()),
            "after": start_timestamp,
            "limit": 100  # Adjust based on your needs
        }
        
        response = await client.get(url, params=params)
        data = response.json()
        
        if isinstance(data, list):
            return data
        else:
            logger.error(f"Unexpected response format: {data}")
            return []
    except Exception as e:
        logger.error(f"Error fetching transactions: {str(e)}")
        return []

async def get_account_transactions_rpc(
    address: str, 
    time_window_days: int = DUST_TIME_WINDOW,
    client: httpx.AsyncClient = None
) -> List[Dict[str, Any]]:
    """Fallback method to get transactions using Solana RPC."""
    if not client:
        client = await get_client()
    
    try:
        # First get signatures
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [
                address,
                {"limit": 100}  # Adjust as needed
            ]
        }
        
        response = await client.post(SOLANA_RPC_URL, json=payload)
        data = response.json()
        
        if "result" not in data or not isinstance(data["result"], list):
            logger.error(f"Failed to get signatures: {data}")
            return []
        
        # Filter by time window
        cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(days=time_window_days)
        signatures = []
        
        for sig_info in data["result"]:
            if "blockTime" in sig_info:
                block_time = datetime.datetime.fromtimestamp(sig_info["blockTime"])
                if block_time >= cutoff_time:
                    signatures.append(sig_info["signature"])
        
        # Get transaction details for each signature
        transactions = []
        for signature in signatures:
            tx_data = await get_transaction_by_signature(signature, client)
            if tx_data:
                transactions.append(tx_data)
        
        return transactions
    except Exception as e:
        logger.error(f"Error fetching transactions from RPC: {str(e)}")
        return []

async def get_transaction_by_signature(
    signature: str,
    client: httpx.AsyncClient = None
) -> Optional[Dict[str, Any]]:
    """Get transaction details by signature."""
    if not client:
        client = await get_client()
    
    try:
        # Try Helius first if available
        if HELIUS_API_KEY:
            url = f"https://api.helius.xyz/v0/transactions/{signature}"
            params = {"api-key": HELIUS_API_KEY}
            
            response = await client.get(url, params=params)
            if response.status_code == 200:
                return response.json()
        
        # Fall back to RPC
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {"encoding": "json", "maxSupportedTransactionVersion": 0}
            ]
        }
        
        response = await client.post(SOLANA_RPC_URL, json=payload)
        data = response.json()
        
        if "result" in data and data["result"]:
            return data["result"]
        else:
            logger.error(f"Failed to get transaction: {data}")
            return None
    except Exception as e:
        logger.error(f"Error getting transaction {signature}: {str(e)}")
        return None

def extract_dust_transactions(
    transactions: List[Dict[str, Any]], 
    address: str
) -> tuple:
    """
    Extract dust transactions from transaction list.
    Returns (dust_received, dust_sent, dust_senders, dust_recipients)
    """
    dust_received = []
    dust_sent = []
    dust_senders = set()
    dust_recipients = set()
    total_dust_amount = 0.0
    first_dust_date = None
    last_dust_date = None
    
    for tx in transactions:
        # Structure depends on whether from Helius or RPC
        if "instructions" in tx:
            # Helius format
            for instruction in tx.get("instructions", []):
                if instruction.get("type") == "SOL_TRANSFER":
                    amount_sol = instruction.get("amount", 0) / 1_000_000_000
                    from_address = instruction.get("source", "")
                    to_address = instruction.get("destination", "")
                    timestamp = tx.get("timestamp", datetime.datetime.utcnow().isoformat())
                    signature = tx.get("signature", "")
                    
                    if MIN_DUST_THRESHOLD <= amount_sol <= DUST_THRESHOLD:
                        tx_info = {
                            "signature": tx.get("signature", ""),
                            "timestamp": timestamp,
                            "from_address": from_address,
                            "to_address": to_address,
                            "amount_sol": amount_sol
                        }
                        
                        # Update date tracking
                        tx_date = timestamp.split("T")[0] if isinstance(timestamp, str) else None
                        if tx_date:
                            if first_dust_date is None or tx_date < first_dust_date:
                                first_dust_date = tx_date
                            if last_dust_date is None or tx_date > last_dust_date:
                                last_dust_date = tx_date
                        
                        if to_address.lower() == address.lower():
                            dust_received.append(tx_info)
                            dust_senders.add(from_address)
                            total_dust_amount += amount_sol
                        elif from_address.lower() == address.lower():
                            dust_sent.append(tx_info)
                            dust_recipients.add(to_address)
        else:
            # RPC format - need to parse message.instructions
            meta = tx.get("meta", {})
            transaction = tx.get("transaction", {})
            message = transaction.get("message", {})
            
            # Try to extract transfers from post balances
            if "postBalances" in meta and "preBalances" in meta and "accountKeys" in message:
                account_keys = message.get("accountKeys", [])
                pre_balances = meta.get("preBalances", [])
                post_balances = meta.get("postBalances", [])
                
                # Look for balance changes that might be transfers
                for i in range(len(account_keys)):
                    if i < len(pre_balances) and i < len(post_balances):
                        balance_change = (post_balances[i] - pre_balances[i]) / 1_000_000_000
                        
                        if MIN_DUST_THRESHOLD <= abs(balance_change) <= DUST_THRESHOLD:
                            # This might be a dust transfer
                            # Try to determine sender/recipient (simplified)
                            if balance_change < 0 and account_keys[i].lower() == address.lower():
                                # Address sent dust
                                # Find potential recipient
                                for j in range(len(account_keys)):
                                    if j != i and j < len(pre_balances) and j < len(post_balances):
                                        recipient_change = (post_balances[j] - pre_balances[j]) / 1_000_000_000
                                        if recipient_change > 0 and abs(recipient_change) < DUST_THRESHOLD:
                                            to_address = account_keys[j]
                                            dust_recipients.add(to_address)
                                            
                                            tx_info = {
                                                "signature": tx.get("transaction", {}).get("signatures", [""])[0],
                                                "timestamp": datetime.datetime.fromtimestamp(tx.get("blockTime", 0)).isoformat(),
                                                "from_address": from_address,
                                                "to_address": address,
                                                "amount_sol": abs(balance_change)
                                            }
                                            dust_received.append(tx_info)
                                            
                                            # Update date tracking
                                            tx_date = tx_info["timestamp"].split("T")[0]
                                            if first_dust_date is None or tx_date < first_dust_date:
                                                first_dust_date = tx_date
                                            if last_dust_date is None or tx_date > last_dust_date:
                                                last_dust_date = tx_date
                                            
                                            break
    
    return (dust_received, dust_sent, dust_senders, dust_recipients, 
            total_dust_amount, first_dust_date, last_dust_date)

def detect_address_poisoning(
    address: str,
    transactions: List[Dict[str, Any]],
    known_addresses: Optional[List[str]] = None
) -> tuple:
    """
    Detect potential address poisoning attempts.
    Returns (similar_addresses, prefix_matches, poisoning_transactions)
    """
    similar_addresses = []
    prefix_matches = []
    poisoning_transactions = []
    
    # Get all unique addresses from transactions
    transaction_addresses = set()
    for tx in transactions:
        # Extract addresses based on transaction format
        if "instructions" in tx:
            # Helius format
            for instruction in tx.get("instructions", []):
                if instruction.get("type") == "SOL_TRANSFER":
                    transaction_addresses.add(instruction.get("source", ""))
                    transaction_addresses.add(instruction.get("destination", ""))
        else:
            # RPC format
            transaction = tx.get("transaction", {})
            message = transaction.get("message", {})
            if "accountKeys" in message:
                transaction_addresses.update(message.get("accountKeys", []))
    
    # Add known addresses if provided
    if known_addresses:
        transaction_addresses.update(known_addresses)
    
    # Remove the address being analyzed
    if address in transaction_addresses:
        transaction_addresses.remove(address)
    
    # Check for prefix matches
    address_prefix = address[:ADDRESS_PREFIX_LENGTH]
    for other_address in transaction_addresses:
        # Check prefix match
        if other_address.startswith(address_prefix) and other_address != address:
            prefix_matches.append({
                "address": other_address,
                "match_type": "prefix",
                "match_length": len(os.path.commonprefix([address, other_address]))
            })
        
        # Check Levenshtein distance for similar addresses
        distance = Levenshtein.distance(address, other_address)
        if distance <= LEVENSHTEIN_THRESHOLD and other_address != address:
            similar_addresses.append({
                "address": other_address,
                "match_type": "levenshtein",
                "distance": distance
            })
    
    # Find transactions involving similar addresses
    for tx in transactions:
        is_poisoning_tx = False
        
        # Check if any similar or prefix-matching address is involved
        similar_and_prefix = [item["address"] for item in similar_addresses + prefix_matches]
        
        if "instructions" in tx:
            # Helius format
            for instruction in tx.get("instructions", []):
                if instruction.get("type") == "SOL_TRANSFER":
                    source = instruction.get("source", "")
                    destination = instruction.get("destination", "")
                    amount_sol = instruction.get("amount", 0) / 1_000_000_000
                    
                    if source in similar_and_prefix or destination in similar_and_prefix:
                        is_poisoning_tx = True
                        
                        poisoning_tx_info = {
                            "signature": tx.get("signature", ""),
                            "timestamp": tx.get("timestamp", ""),
                            "from_address": source,
                            "to_address": destination,
                            "amount_sol": amount_sol,
                            "similar_to": address
                        }
                        poisoning_transactions.append(poisoning_tx_info)
        else:
            # RPC format
            transaction = tx.get("transaction", {})
            message = transaction.get("message", {})
            account_keys = message.get("accountKeys", [])
            
            if any(addr in similar_and_prefix for addr in account_keys):
                is_poisoning_tx = True
                
                poisoning_tx_info = {
                    "signature": tx.get("transaction", {}).get("signatures", [""])[0],
                    "timestamp": datetime.datetime.fromtimestamp(tx.get("blockTime", 0)).isoformat(),
                    "involved_addresses": [addr for addr in account_keys if addr in similar_and_prefix],
                    "similar_to": address
                }
                poisoning_transactions.append(poisoning_tx_info)
    
    return (similar_addresses, prefix_matches, poisoning_transactions)

def calculate_dusting_confidence(
    dust_received_count: int,
    dust_sent_count: int,
    unique_dust_senders: int,
    total_dust_amount: float
) -> float:
    """Calculate confidence score for dusting classification."""
    # Base score
    score = 0.0
    
    # More dust transactions = higher confidence
    if dust_received_count > 0:
        score += min(dust_received_count / 10, 0.4)  # Up to 0.4 based on received dust count
    
    # More unique senders = higher confidence
    if unique_dust_senders > 0:
        score += min(unique_dust_senders / 5, 0.3)  # Up to 0.3 based on unique senders
    
    # Larger dust amount slightly reduces confidence (real dust is typically very small)
    if total_dust_amount > 0:
        amount_factor = 1.0 - min(total_dust_amount / DUST_THRESHOLD, 0.3)
        score += amount_factor * 0.1  # Up to 0.1
    
    # If address sent more dust than received, probably a duster itself
    if dust_sent_count > dust_received_count * 2 and dust_sent_count > 3:
        score += 0.2
    
    return min(score, 1.0)

def calculate_poisoning_confidence(
    similar_addresses: List[Dict[str, Any]],
    prefix_matches: List[Dict[str, Any]]
) -> float:
    """Calculate confidence score for address poisoning classification."""
    # Base score
    score = 0.0
    
    # More similar addresses = higher confidence
    if similar_addresses:
        score += min(len(similar_addresses) / 3, 0.4)  # Up to 0.4 based on similar addresses
        
        # Add score based on similarity
        avg_distance = sum(item["distance"] for item in similar_addresses) / len(similar_addresses)
        score += (LEVENSHTEIN_THRESHOLD - avg_distance) / LEVENSHTEIN_THRESHOLD * 0.2  # Up to 0.2
    
    # More prefix matches = higher confidence
    if prefix_matches:
        score += min(len(prefix_matches) / 3, 0.3)  # Up to 0.3 based on prefix matches
        
        # Add score based on prefix length
        avg_length = sum(item["match_length"] for item in prefix_matches) / len(prefix_matches)
        score += min(avg_length / 10, 0.1)  # Up to 0.1 based on match length
    
    return min(score, 1.0)

# -------------------- API Endpoints --------------------

@app.get("/")
async def root():
    """API root endpoint with basic information."""
    return {
        "name": "Solana Dust & Address Poisoning Detection API",
        "version": "1.0.0",
        "endpoints": [
            "/analyze/address/{address}",
            "/analyze/addresses",
            "/analyze/transactions"
        ],
        "documentation": "/docs"
    }

@app.get("/analyze/address/{address}", response_model=AddressAnalysisResponse)
async def analyze_address(
    address: str,
    time_window_days: int = Query(DUST_TIME_WINDOW, ge=1, le=365),
    include_transactions: bool = Query(False),
    client: httpx.AsyncClient = Depends(get_client)
):
    """Analyze a single Solana address for dusting and poisoning."""
    try:
        # Validate address format
        SolanaAddress(address=address)
        
        # Get transactions
        transactions = await get_account_transactions(address, time_window_days, client)
        
        # Extract dust transactions
        (dust_received, dust_sent, dust_senders, dust_recipients,
         total_dust_amount, first_dust_date, last_dust_date) = extract_dust_transactions(transactions, address)
        
        # Detect address poisoning
        similar_addresses, prefix_matches, poisoning_transactions = detect_address_poisoning(
            address, transactions
        )
        
        # Calculate confidence scores
        dusting_score = calculate_dusting_confidence(
            len(dust_received), len(dust_sent), len(dust_senders), total_dust_amount
        )
        poisoning_score = calculate_poisoning_confidence(similar_addresses, prefix_matches)
        
        # Determine if this is dusting/poisoning
        is_dusting = dusting_score > 0.5 and (len(dust_received) > 0 or len(dust_sent) > DUST_SENDER_THRESHOLD)
        is_poisoning = poisoning_score > 0.5 and (len(similar_addresses) > 0 or len(prefix_matches) > 0)
        
        # Create response
        dusting_result = DustingResult(
            is_dusting=is_dusting,
            confidence_score=dusting_score,
            dust_received_count=len(dust_received),
            dust_sent_count=len(dust_sent),
            unique_dust_senders=len(dust_senders),
            total_dust_amount=total_dust_amount,
            first_dust_date=first_dust_date,
            last_dust_date=last_dust_date,
            transactions=dust_received if include_transactions else None
        )
        
        poisoning_result = PoisoningResult(
            is_poisoning=is_poisoning,
            confidence_score=poisoning_score,
            similar_addresses=similar_addresses,
            prefix_matches=prefix_matches,
            transactions=poisoning_transactions if include_transactions else None
        )
        
        # Determine label
        if is_dusting and is_poisoning:
            label = "both"
        elif is_dusting:
            label = "dusting"
        elif is_poisoning:
            label = "address_poisoning"
        else:
            label = "benign"
        
        return AddressAnalysisResponse(
            address=address,
            label=label,
            dusting=dusting_result,
            poisoning=poisoning_result
        )
    
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error analyzing address {address}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/addresses", response_model=List[AddressAnalysisResponse])
async def analyze_multiple_addresses(
    request: MultiAddressAnalysisRequest,
    client: httpx.AsyncClient = Depends(get_client)
):
    """Analyze multiple Solana addresses for dusting and poisoning."""
    try:
        results = []
        
        # Process each address
        for address in request.addresses:
            # Reuse single address endpoint
            result = await analyze_address(
                address, 
                request.time_window_days,
                request.include_transactions,
                client
            )
            results.append(result)
        
        return results
    
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error analyzing multiple addresses: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/transactions", response_model=List[TransactionAnalysisResponse])
async def analyze_transactions(
    request: TransactionAnalysisRequest,
    client: httpx.AsyncClient = Depends(get_client)
):
    """Analyze a list of transaction signatures for dusting and poisoning."""
    try:
        results = []
        
        # Get transaction details for each signature
        for signature in request.signatures:
            # Validate signature format
            TransactionSignature(signature=signature)
            
            tx_data = await get_transaction_by_signature(signature, client)
            
            if not tx_data:
                results.append(TransactionAnalysisResponse(
                    signature=signature,
                    is_dust=False,
                    is_poisoning=False,
                    label="not_found",
                    confidence_score=0.0,
                    details={"error": "Transaction not found"}
                ))
                continue
            
            # Initialize analysis results
            is_dust = False
            is_poisoning = False
            confidence_score = 0.0
            details = {} if request.include_details else None
            
            # Extract transaction details
            involved_addresses = set()
            transfer_amount = 0.0
            
            # Extract data based on format (Helius vs RPC)
            if "instructions" in tx_data:
                # Helius format
                for instruction in tx_data.get("instructions", []):
                    if instruction.get("type") == "SOL_TRANSFER":
                        transfer_amount = instruction.get("amount", 0) / 1_000_000_000
                        from_address = instruction.get("source", "")
                        to_address = instruction.get("destination", "")
                        
                        involved_addresses.add(from_address)
                        involved_addresses.add(to_address)
                        
                        if details is not None:
                            details["from_address"] = from_address
                            details["to_address"] = to_address
                            details["amount_sol"] = transfer_amount
                            details["timestamp"] = tx_data.get("timestamp", "")
            else:
                # RPC format
                transaction = tx_data.get("transaction", {})
                message = transaction.get("message", {})
                meta = tx_data.get("meta", {})
                
                # Extract addresses
                if "accountKeys" in message:
                    involved_addresses.update(message.get("accountKeys", []))
                    
                    if details is not None:
                        details["involved_addresses"] = message.get("accountKeys", [])
                
                # Try to determine transfer amount
                if "postBalances" in meta and "preBalances" in meta:
                    pre_balances = meta.get("preBalances", [])
                    post_balances = meta.get("postBalances", [])
                    
                    # Look for balance changes that might be transfers
                    for i in range(min(len(pre_balances), len(post_balances))):
                        balance_change = (post_balances[i] - pre_balances[i]) / 1_000_000_000
                        if abs(balance_change) > 0:
                            transfer_amount = abs(balance_change)
                            break
                
                if details is not None:
                    details["amount_sol"] = transfer_amount
                    details["block_time"] = datetime.datetime.fromtimestamp(
                        tx_data.get("blockTime", 0)
                    ).isoformat()
            
            # Check if this is a dust transaction
            if MIN_DUST_THRESHOLD <= transfer_amount <= DUST_THRESHOLD:
                is_dust = True
                confidence_score = 0.7 + ((DUST_THRESHOLD - transfer_amount) / DUST_THRESHOLD * 0.3)
            
            # TODO: More comprehensive poisoning detection would require context of wallet history
            # This is a simple check for now
            if len(involved_addresses) >= 2:
                # Check if any addresses have similar prefixes
                address_list = list(involved_addresses)
                for i in range(len(address_list)):
                    for j in range(i + 1, len(address_list)):
                        addr1 = address_list[i]
                        addr2 = address_list[j]
                        
                        # Check prefix similarity
                        common_prefix_len = len(os.path.commonprefix([addr1, addr2]))
                        if common_prefix_len >= ADDRESS_PREFIX_LENGTH:
                            is_poisoning = True
                            poisoning_confidence = min(common_prefix_len / 10, 0.8)
                            
                            if poisoning_confidence > confidence_score:
                                confidence_score = poisoning_confidence
                            
                            if details is not None:
                                details["similar_addresses"] = [addr1, addr2]
                                details["common_prefix_length"] = common_prefix_len
                            
                            break
                        
                        # Check Levenshtein distance
                        distance = Levenshtein.distance(addr1, addr2)
                        if distance <= LEVENSHTEIN_THRESHOLD:
                            is_poisoning = True
                            poisoning_confidence = (LEVENSHTEIN_THRESHOLD - distance) / LEVENSHTEIN_THRESHOLD * 0.8
                            
                            if poisoning_confidence > confidence_score:
                                confidence_score = poisoning_confidence
                            
                            if details is not None:
                                details["similar_addresses"] = [addr1, addr2]
                                details["levenshtein_distance"] = distance
                            
                            break
            
            # Determine label
            if is_dust and is_poisoning:
                label = "both"
            elif is_dust:
                label = "dusting"
            elif is_poisoning:
                label = "address_poisoning"
            else:
                label = "benign"
            
            results.append(TransactionAnalysisResponse(
                signature=signature,
                is_dust=is_dust,
                is_poisoning=is_poisoning,
                label=label,
                confidence_score=confidence_score,
                details=details
            ))
        
        return results
    
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error analyzing transactions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
 0)).isoformat(),
                                                "from_address": address,
                                                "to_address": to_address,
                                                "amount_sol": abs(balance_change)
                                            }
                                            dust_sent.append(tx_info)
                                            
                                            # Update date tracking
                                            tx_date = tx_info["timestamp"].split("T")[0]
                                            if first_dust_date is None or tx_date < first_dust_date:
                                                first_dust_date = tx_date
                                            if last_dust_date is None or tx_date > last_dust_date:
                                                last_dust_date = tx_date
                                            
                                            break
                            elif balance_change > 0 and account_keys[i].lower() == address.lower():
                                # Address received dust
                                # Find potential sender
                                for j in range(len(account_keys)):
                                    if j != i and j < len(pre_balances) and j < len(post_balances):
                                        sender_change = (post_balances[j] - pre_balances[j]) / 1_000_000_000
                                        if sender_change < 0 and abs(sender_change) > MIN_DUST_THRESHOLD:
                                            from_address = account_keys[j]
                                            dust_senders.add(from_address)
                                            total_dust_amount += abs(balance_change)
                                            
                                            tx_info = {
                                                "signature": tx.get("transaction", {}).get("signatures", [""])[0],
                                                "timestamp": datetime.datetime.fromtimestamp(tx.get("blockTime",