# Project-1: Designing and Modelling a Real-World Software Feature System
Computational Thinking and Problem Solving (CMPS-3000-BSA)


# E-Commerce CLI System

## Overview

This repository contains a Python-based command-line simulation of an e-commerce system. The implementation operationalizes the logical models developed in earlier design phases (truth tables, access control logic, and business rule pseudocode) into executable control flow.

The system is intentionally implemented as a CLI application to foreground logic, state management, and rule enforcement rather than interface complexity.

The program models authentication, role-based authorization, product management, cart operations, transactional processing, and rule-based fraud detection using in-memory data structures.

---

## Design Objectives

The primary objective of this implementation is to demonstrate:

- Transformation of formal logic (truth tables and predicates) into conditional execution  
- Explicit role-based access control (RBAC)  
- Deterministic enforcement of business constraints  
- Controlled state mutation  
- Structured validation prior to transactional commit  
- Simulation of risk assessment using threshold-based heuristics  

---

## System Architecture

### Data Model

The system models three core entities using Python `dataclasses`:

- `User`
- `Product`
- `Order`

These structures simulate relational table rows but remain in-memory for simplicity and reproducibility.

System state is maintained using three primary collections:

- `USERS` → authentication and authorization records  
- `PRODUCTS` → inventory catalog  
- `ORDERS` → transaction history  

No persistent storage layer is used. The system resets on termination.

---

### Authentication Logic

Authentication enforces:

- Username/password validation  
- Account lockout after five failed attempts  
- Reset of failed-attempt counter upon successful login  

---

### Role-Based Access Control (RBAC)

Roles:

- `buyer`
- `seller`
- `admin`

Access decisions are determined via explicit predicate functions:

- Admin access requires `role == admin` and account not locked  
- Seller tools are accessible to `seller` and `admin`  
- Buyers are restricted to browsing and purchasing  

This models hierarchical privilege separation and controlled access domains.

---

### Product and Inventory Logic

Product search supports:

- Keyword matching  
- Maximum price filtering  
- Boolean flags (trending, on sale)  

Inventory validation occurs before checkout to prevent overselling.

Inventory reduction is executed only after successful payment validation, simulating transactional integrity.

---

### Discount Engine

The discount module demonstrates rule stacking with bounded enforcement.

Implemented rules:

- 10% discount on first order  
- Flat and percentage-based coupon logic  
- Maximum discount cap of 30% of subtotal  

This models cumulative rule application with upper-bound constraint enforcement.

---

### Payment Validation

Payment logic enforces:

- Accepted method verification  
- Positive transaction totals  

This simulates input validation prior to transaction commit.

---

### Fraud Detection (Rule-Based)

The fraud module demonstrates threshold-based anomaly detection using simple heuristics:

- More than three orders within 60 seconds  
- High-value debit transactions exceeding a defined threshold  

Orders meeting these conditions are flagged for review.

---

## Execution

### Requirements

- Python 3.10+
- No external dependencies

---

### Run

From the project root directory:

```bash
python ecommerce_cli.py
```

---

## Implementation Characteristics

- Pure Python (standard library only)  
- Deterministic execution model  
- Explicit state mutation  
- In-memory data structures simulating relational tables  
- No external services or third-party dependencies  
- No concurrency model  
- No persistence layer  

The absence of persistence and cryptographic password storage is intentional.  

---

## Limitations

- Application state is not persisted between runs  
- Passwords are stored in plaintext (simulation context only)  
- No database normalization or indexing  
- Fraud detection is rule-based and deterministic  
- No asynchronous or distributed components  


---

## Potential Extensions

- JSON or SQLite persistence layer
- Secure password hashing (e.g., bcrypt)  
- Unit test suite for business rule validation  
- Structured logging and audit trail  
- REST API implementation (e.g., Flask-based service layer)  
- Replacement of rule-based fraud logic with statistical or ML-based anomaly detection  

---

## Repository Structure
```
Project-1
  ├── ecommerce_cli.py
  ├── README.md
  └── .gitignore
```

