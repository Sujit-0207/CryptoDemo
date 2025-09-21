# CryptoDemo

A Streamlit web app demonstrating three cryptographic techniques:

-   **Diffie–Hellman Key Exchange**
-   **HMAC (SHA-256)**
-   **ElGamal Digital Signatures**

## Features

-   Interactive, step-by-step demos for each algorithm
-   Explanations for each cryptographic step in the UI
-   All cryptographic operations use standard Python libraries

## Installation

1. Clone this repository or download the source code.
    ```bash
    git clone github.com/Sujit-0207/CryptoDemo.git
    ```
   
2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the Streamlit app:

```bash
streamlit run app.py
```

The app will open in your browser. Each algorithm is available in its own tab.

## How to Use

### Diffie–Hellman Key Exchange

-   Go to the "Diffie–Hellman Key Exchange" tab.
-   Click **Generate DH Parameters & Keys** to create keys for Party A and Party B.
-   View the public keys for both parties.
-   The app shows the derived shared secret for each party and confirms if they match.
-   Enter a message and click **Encrypt with Shared Secret** to encrypt it with AES.
-   Click **Decrypt with Shared Secret** to decrypt and verify the message.

### HMAC (SHA-256)

-   Go to the "HMAC (SHA-256)" tab.
-   Click **Generate HMAC Key** to create a random key.
-   Enter a message and click **Compute HMAC** to generate the HMAC.
-   Optionally, tamper with the message or HMAC value and click **Verify HMAC** to see verification fail.

### ElGamal Digital Signatures

-   Go to the "ElGamal Digital Signature" tab.
-   Click **Generate ElGamal Keypair** to create a keypair.
-   Enter a message and click **Sign Message** to generate a signature.
-   Optionally, tamper with the message and click **Verify Signature** to see verification fail.

## Project Structure

```
CryptoDemo/
│── app.py                # Streamlit frontend
│── crypto_utils.py       # Core crypto functions (DH, HMAC, ElGamal)
│── requirements.txt      # Dependencies
│── README.md             # Setup + usage instructions
```

## License

MIT
