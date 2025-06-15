# Solana Dust & Address Poisoning Detection API

This project provides a FastAPI-based web API for detecting dusting attacks and address poisoning attempts on the Solana blockchain. It analyzes Solana addresses and transactions to identify suspicious activity, such as small unsolicited transfers (dusting) and lookalike address attacks (address poisoning).

## Features

- **Dusting Detection:** Identifies small SOL transfers (dust) and suspicious sender patterns.
- **Address Poisoning Detection:** Detects addresses similar to the target (by prefix or Levenshtein distance) and related suspicious transactions.
- **Batch Analysis:** Analyze multiple addresses or transactions in a single request.
- **Configurable Parameters:** Time window, thresholds, and detection logic can be tuned via environment variables and request parameters.
- **CORS Enabled:** Ready for integration with web frontends or other services.

## API Endpoints

- `GET /`  
  API root with metadata and available endpoints.

- `GET /analyze/address/{address}`  
  Analyze a single Solana address for dusting and poisoning.  
  **Query Parameters:**  
  - `time_window_days` (default: 30)  
  - `include_transactions` (default: false)

- `POST /analyze/addresses`  
  Analyze multiple addresses.  
  **Body:**  
  ```json
  {
    "addresses": ["address1", "address2"],
    "time_window_days": 30,
    "include_transactions": false
  }
  ```

- `POST /analyze/transactions`  
  Analyze a list of transaction signatures.  
  **Body:**  
  ```json
  {
    "signatures": ["signature1", "signature2"],
    "include_details": true
  }
  ```

## Usage

### Requirements

- Python 3.8+
- [FastAPI](https://fastapi.tiangolo.com/)
- [httpx](https://www.python-httpx.org/)
- [Levenshtein](https://pypi.org/project/python-Levenshtein/)
- [uvicorn](https://www.uvicorn.org/)

Install dependencies:
```sh
pip install fastapi httpx python-Levenshtein uvicorn
```

### Running the API

Set environment variables as needed:
- `HELIUS_API_KEY` (optional, for enhanced Solana transaction data)
- `SOLANA_RPC_URL` (optional, defaults to mainnet-beta)

Start the server:
```sh
uvicorn main:app --reload
```

The API will be available at [http://localhost:8000](http://localhost:8000).

Interactive documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

## License

MIT License. See source code for details.

---

**Disclaimer:** This tool is for informational and research purposes only. Detection results are heuristic and may not be fully accurate.