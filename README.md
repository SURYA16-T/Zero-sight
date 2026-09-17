# ZeroSight: Blind Eligibility Engine

## Privacy-Preserving Eligibility Verification Using Homomorphic Encryption

ZeroSight is a privacy-preserving eligibility verification platform designed for community aid, scholarships, medical subsidies, welfare benefits, and emergency grants.

Traditional eligibility verification requires applicants to submit sensitive personal data—such as annual income, dependent children, medical disability, and senior citizen status—to a central evaluator. This creates serious risks of unauthorized access, database breaches, and mass surveillance.

ZeroSight uses **Paillier Partially Homomorphic Encryption (PHE)** to compute eligibility directly over **encrypted data**. The evaluator receives only mathematical ciphertexts and computes the certified policy formula homomorphically. The applicant decrypts their score locally, ensuring zero plaintext disclosure to the evaluating authority.

---

## Where to Use This Project (Use Cases)

ZeroSight is designed for any scenario where a central authority must evaluate applicants against a mathematical formula without learning their sensitive underlying data. Common use cases include:

- **Government Welfare & Subsidies:** Determining eligibility for food stamps, housing assistance, or unemployment benefits based on income and family size without collecting plaintext tax returns.
- **Academic Scholarships & Grants:** Assessing financial need for student scholarships without exposing family wealth or medical history to the university.
- **Medical Triage & Resource Allocation:** Prioritizing patients for scarce medical resources based on age, pre-existing conditions, and risk factors without violating HIPAA or patient confidentiality.
- **Corporate Grants & Relief Funds:** Distributing emergency funds to employees based on hardship criteria without HR gaining access to intimate personal details.

---

## How It Works

1. **Local Data Processing:** The applicant uploads their documents (JSON, PDF, TXT) to their local machine (or browser). The data never leaves their device.
2. **Key Generation:** A strong, 2048-bit cryptographic key pair is generated locally. The private key is securely encrypted at rest (using Argon2id and AES-GCM) and remains strictly with the applicant.
3. **Homomorphic Encryption:** The applicant's sensitive data (e.g., income = 20000) is encrypted using the public key.
4. **Blind Evaluation:** The encrypted data and the public key are sent to the ZeroSight API Evaluator. The evaluator cannot decrypt the data. Instead, it uses the mathematical properties of Homomorphic Encryption to run the policy formula (e.g., `Score = Base + (Income * Weight)`) directly on the ciphertexts.
5. **Score Return & Local Decryption:** The evaluator returns a single encrypted score. The applicant decrypts this score locally with their private key to determine their eligibility. Neither party learns the other's secrets.

---

## Key Features

1. **Multi-Format Ingestion:** Ingests applicant declarations from `.json`, `.txt`, and `.pdf` files strictly in-memory.
2. **Defensive Parsing & Normalization:** Employs linear-time regex parsing and field alias resolution to normalize data into canonical attributes.
3. **NIST SP 800-57 Compliant Cryptography:** Defaults to **2048-bit Paillier keys** with optional 1024-bit rapid demonstration mode.
4. **Modulo Wrap-Around Protection:** Guards against negative integer underflow/overflow when evaluating negative weights (e.g. `income_weight = -1`).
5. **Strict Trust Boundary Isolation:** Evaluator operates strictly on serialized public keys and ciphertexts with **zero access** to private keys or plaintext storage.
6. **Safe Serialization:** Replaces unsafe Python `pickle` with a safe JSON serializer (`bee/serializer.py`).
7. **Policy Integrity Verification:** Computes canonical SHA-256 digests of policy definitions to detect tampering.
8. **Cryptographic Proof Receipts:** Exports downloadable Markdown and JSON certificates of verification.
9. **Side-by-Side Parity Comparison:** Mathematically proves that homomorphic computation matches plaintext computation.

---

## System Architecture

The architecture relies on a strict trust boundary between the applicant and the evaluator, fortified by a dedicated API layer and secure key management.

```text
Applicant Machine (Local Browser / Device)            Subsidy Evaluator (Remote API Server)
┌──────────────────────────────────────────┐          ┌───────────────────────────────────┐
│ 1. Upload Document (.json, .txt, .pdf)   │          │                                   │
│ 2. Local In-Memory Parser & Extractor    │          │                                   │
│ 3. Client Validation (Bounds & Types)    │          │                                   │
│ 4. Paillier Keygen & Secure Storage      │          │                                   │
│    - Private Key wrapped with Argon2/AES │          │                                   │
│ 5. Encrypt Sensitive Inputs Locally      │          │                                   │
│    Enc(income), Enc(children), etc.      │          │                                   │
│                                          │          │                                   │
│    ─────── Send Ciphertexts & Public Key ─────────► │ 6. FastAPI Security Gateway       │
│                                          │          │    - Rate Limiting & Auth         │
│                                          │          │    - Replay Attack Protection     │
│                                          │          │ 7. Blind Homomorphic Evaluation   │
│                                          │          │    Enc(Score) = Enc(Base) + ...   │
│                                          │          │ 8. Tamper-Proof Audit Logging     │
│                                          │          │                                   │
│    ◄────── Return Encrypted Score ───────────────── │    (Zero Plaintext Knowledge)     │
│                                          │          │                                   │
│ 9. Local Decryption with Private Key     │          │                                   │
│ 10. Compare Decrypted Score vs Threshold │          │                                   │
│ 11. Generate Verifiable Proof Receipt    │          │                                   │
└──────────────────────────────────────────┘          └───────────────────────────────────┘
```

---

## Installation & Setup

### 1. Prerequisites

- Python 3.9+ (Make sure Python is added to your PATH).
- Git (optional, for cloning).

### 2. Step-by-Step Installation for Windows OS

Follow these exact steps to get ZeroSight running on a Windows environment:

#### Step 1: Open PowerShell

Press `Win + R`, type `powershell`, and hit Enter.

#### Step 2: Clone or Download the Repository

Navigate to where you want to store the project. If you have the folder already, navigate into it:

```powershell
cd C:\path\to\Zerosight
```

#### Step 3: Create a Python Virtual Environment

This keeps dependencies isolated from your main system.

```powershell
python -m venv .venv
```

#### Step 4: Activate the Virtual Environment

You must do this every time you open a new terminal to run the project.

```powershell
.\.venv\Scripts\activate
```

*(If you see an execution policy error, run `Set-ExecutionPolicy Unrestricted -Scope CurrentUser` first and try again).*

#### Step 5: Install Required Dependencies

```powershell
pip install -r requirements.txt
```

#### Step 6: Set up Environment Variables

Copy the example environment file to create your local config.

```powershell
copy .env.example .env
```

You are now ready to run the application on Windows!

---

### 3. Installation for macOS / Linux

```bash
# Navigate to the repository
cd Zerosight

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
```

---

## Running the Applications

### 1. Run the Security Evaluator API (Backend)

Before making evaluations, you need to start the secure FastAPI evaluator server in a terminal.

**On Windows (PowerShell):**
```powershell
.\.venv\Scripts\activate
uvicorn api.main:app --reload --port 8000
```

**On macOS / Linux:**
```bash
source .venv/bin/activate
uvicorn api.main:app --reload --port 8000
```
*The API will now be running at `http://localhost:8000`.*

### 2. Interactive Web Application (Streamlit)

Open a **new, second terminal window** (keep the first one running), activate your environment again, and launch the dashboard:

**On Windows (PowerShell):**
```powershell
.\.venv\Scripts\activate
streamlit run app.py --server.port 8501
```

**On macOS / Linux:**
```bash
source .venv/bin/activate
streamlit run app.py --server.port 8501
```

Open your browser to `http://localhost:8501` to test document uploads and interact with the zero-knowledge verification system!

### 3. Command Line Interface (CLI)

Run automated batch evaluations directly from your terminal:

```bash
# Evaluate an eligible applicant (JSON)
python main_cli.py sample_files/sample.json --inspect

# Evaluate with output proof receipt saved to a file
python main_cli.py sample_files/sample.json --receipt proof.md

# Evaluate an applicant from a PDF document
python main_cli.py sample_files/sample.pdf

# Evaluate from a plain text declaration
python main_cli.py sample_files/sample.txt

# Specify custom policy or key size
python main_cli.py sample_files/sample_boundary.json --key-size 2048
```

---

## Automated Test Suite

ZeroSight includes a comprehensive test suite covering parsers, normalizers, bounds validators, crypto operations, evaluator endpoints, and security attack simulations:

```bash
# Run full test suite with verbose output
pytest -v
```

### Tested Scenarios

- **Eligible Applicant:** Income $18,000, 2 children $\to$ Decrypted Score 38,000 $\ge$ 30,000 (`ELIGIBLE`).
- **Ineligible Applicant:** Income $45,000, 1 child $\to$ Decrypted Score 8,000 $<$ 30,000 (`NOT ELIGIBLE`).
- **Exact Boundary:** Income $23,000, 1 child $\to$ Decrypted Score 30,000 $==$ 30,000 (`ELIGIBLE`).
- **Policy Hash Tampering:** Evaluator payload rejects tampered policy definitions.
- **Modulo Wrap-Around Protection:** Negative intermediate scores (e.g. Income $500,000 $\to$ Score $-450,000$) safely decrypt without overflow.
- **Anti-DoS Constraints:** Rejects payloads exceeding 5 MB or corrupted PDF streams.

---

## Project Structure

```text
Zerosight/
├── app.py                      # Interactive Streamlit Web Application
├── main_cli.py                 # Command-line evaluation interface
├── requirements.txt            # Project dependencies
├── pytest.ini                  # Pytest configuration
├── README.md                   # System documentation
│
├── bee/                        # Blind Eligibility Engine Core Package
│   ├── __init__.py
│   ├── config.py               # Security limits, key sizes, field aliases
│   ├── parser.py               # Memory-safe parser (JSON, TXT, PDF)
│   ├── extractor.py            # Field normalization and type casting
│   ├── validator.py            # Range invariants and policy rules
│   ├── crypto_utils.py         # 2048-bit Paillier keygen, encryption, decryption
│   ├── policy.py               # Policy loader and canonical SHA-256 hashing
│   ├── evaluator.py            # Homomorphic evaluator (zero-plaintext)
│   ├── comparison.py           # Client-side parity comparison
│   ├── serializer.py           # Safe JSON serialization (no pickle)
│   └── audit.py                # Verifiable receipt and markdown certificate
│
├── policies/
│   └── community_welfare_v1.json  # Certified welfare subsidy policy
│
├── sample_files/
│   ├── sample.json             # Eligible test applicant
│   ├── sample.txt              # Plain text declaration
│   ├── sample_not_eligible.json# Non-eligible applicant
│   ├── sample_boundary.json    # Exact threshold test case
│   └── sample.pdf              # Valid PDF document test case
│
└── tests/
    ├── test_parser.py          # Document parsing tests
    ├── test_extractor.py       # Normalization and alias tests
    ├── test_validator.py       # Bounds validation tests
    ├── test_crypto.py          # Cryptography and serialization tests
    ├── test_evaluator.py       # Homomorphic evaluation tests
    ├── test_comparison.py      # Result parity tests
    └── test_security.py        # Threat mitigation and tamper tests
```

---

## License & Compliance

This software is developed for privacy-preserving computation demonstrations under standard academic and opensource licensing.
