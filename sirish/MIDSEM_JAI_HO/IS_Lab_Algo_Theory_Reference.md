# **IS LAB – QUICK ALGORITHM REFERENCE** 

_Labs 1–6 · Focus: algorithms, formulas, access-control models_ 

LAB 1 – Classical / Basic Symmetric Ciphers 

### 1.1  Additive (Caesar / Shift) Cipher 

**Type:** Monoalphabetic substitution. Key k  Z₂₆∈ **Encrypt:** `C = (P + k) mod 26` **Decrypt:** `P = (C – k) mod 26` **Key=20 example:** "A"(0) → (0+20)mod26=20 → "U" Letters are mapped A=0, B=1, … Z=25. Non-alpha chars pass through unchanged. 

### 1.2  Multiplicative Cipher 

**Condition:** Key k must be coprime with 26 (gcd(k,26)=1). Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25 **Encrypt:** `C = (P × k) mod 26` **Decrypt:** `P = (C × k` ⁻ `¹) mod 26` 

**k⁻¹:** modular inverse of k mod 26. Example: k=15 → k⁻¹=7 (because 15×7=105≡1 mod26) 

### 1.3  Affine Cipher 

**Key:** pair (a, b) where gcd(a,26)=1 **Encrypt:** `C = (a×P + b) mod 26` **Decrypt:** `P = a` ⁻ `¹×(C – b) mod 26` 

It is a combination of multiplicative (a) and additive (b) ciphers. 

### 1.4  Vigenère Cipher  [Polyalphabetic] 

**Key:** a word/phrase. Repeat key to match plaintext length. **Encrypt:** `C = (P + K ᵢ ᵢ ᵢ ) mod 26` **Decrypt:** `P = (C – K ᵢ ᵢ ᵢ ) mod 26` Each character is shifted by the corresponding key character value. 

### 1.5  AutoKey Cipher 

**Key stream:** `k = (k ₁ , P ₁ , P ₂ , P ₃ , …)` **Encrypt:** `C = (P + k ᵢ ᵢ ᵢ ) mod 26` **Decrypt:** `P = (C – k ᵢ ᵢ ᵢ ) mod 26` 

After the initial key character, the plaintext itself becomes the key. 

### 1.6  Playfair Cipher 

**Matrix:** 5×5 grid filled with keyword (no duplicates, I/J merged), then remaining letters. 

- Split plaintext into digraphs (pairs); insert X between double letters, pad with X if odd length. 

- Same row → take the letter to the right (wrap around). 

- Same column → take the letter below (wrap around). 

- Otherwise → take the letter in the same row but the partner's column. 

**Decrypt:** reverse the above rules (left/up instead of right/down). 

### 1.7  Hill Cipher  [Block cipher using matrix] 

**Key:** n×n matrix K (invertible mod 26). **Encrypt:** `C = K × P (mod 26)   [column vectors of length n]` **Decrypt:** `P = K` ⁻ `¹ × C (mod 26)` For 2×2 key K=[[a,b],[c,d]]: K⁻¹ = det⁻¹ × [[d,−b],[−c,a]] mod 26 

### 1.8  Transposition Ciphers 

**Keyless:** Write text row-by-row into an n-column grid, read column-by-column. **Keyed:** Columns are reordered by sorting the key alphabetically. 

## LAB 2 – Advanced Symmetric Key Ciphers (DES & AES) 

### 2.1  DES – Data Encryption Standard 

**Block size:** 64 bits  |  Key: 56 bits (64-bit input, 8 parity bits discarded) **Rounds:** 16 Feistel rounds 

Key Schedule 

- 64-bit key → remove 8 parity bits → 56 bits 

- Split into two 28-bit halves C and D 

- Each round: left-rotate C and D by schedule (1 or 2 bits) 

- Apply PC-2 permutation → 48-bit round key Kᵢ 

Each Round (Feistel) 

- Split 64-bit block into L (left 32) and R (right 32) 

- Expand R: 32→48 bits via E-table 

- XOR with round key Kᵢ (48 bits) 

- 8 S-boxes: 48→32 bits (each 6-bit input → 4-bit output) 

- P-box permutation: shuffle 32 bits 

- New R = P-box output XOR old L;  New L = old R 

**Decryption:** Same structure, round keys applied in reverse order. 

### 2.2  Triple DES (3DES) 

**Algorithm:** `C = E` ₖ₃ `(D` ₖ₂ `(E` ₖ₁ `(P)))` **Key options:** 3 independent keys (168 bits effective) or K1=K3 (112 bits effective). 

**Decrypt:** `P = D` ₖ₁ `(E` ₖ₂ `(D` ₖ₃ `(C)))` 

### 2.3  AES – Advanced Encryption Standard 

**Block size:** 128 bits (4×4 byte state matrix)  |  Key: 128/192/256 bits  |  Rounds: 10/12/14 

#### Key Expansion 

Initial 128-bit key → expand into (Nr+1)×128 bits using SubWord, RotWord, XOR with Rcon. 

Round Structure (each main round) 

|**Step**|**What it does**|
|---|---|
|SubBytes|Each byte replaced via AES S-box (non-linear substitution using GF(2⁸))|
|ShiftRows|Row 0: no shift; Row 1: shift left 1; Row 2: shift left 2; Row 3: shift left 3|
|MixColumns|Each column multiplied by fixed polynomial in GF(2⁸) → diffusion|
|AddRoundKey|XOR state with 128-bit round key|



**Final Round:** SubBytes → ShiftRows → AddRoundKey  (no MixColumns) **Decryption:** InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns (applied in reverse). 

### 2.4  Block Cipher Modes of Operation 

|**Mode**|**Formula**|**Notes**|
|---|---|---|
|ECB|Cᵢ = E(Pᵢ)|No IV. Same block → same cipher. Weak for<br>patterns.|
|CBC|Cᵢ = E(Pᵢ XOR Cᵢ₋₁)|IV needed. Error propagates. Most common.|
|CFB|Cᵢ = Pᵢ XOR E(Cᵢ₋₁)|Stream-mode feel. IV needed.|
|OFB|Cᵢ = Pᵢ XOR Oᵢ; Oᵢ=E(Oᵢ₋₁)|Pre-computable keystream. IV needed.|
|CTR|Cᵢ = Pᵢ XOR E(Nonce‖counter)|Parallelisable. Nonce+counter needed.|



## LAB 3 – Asymmetric Key Ciphers 

### 3.1  RSA 

Key Generation 

- Choose two large primes p and q 

- n = p × q  (modulus; public) 

- φ(n) = (p−1)(q−1) 

- Choose e: 1 < e < φ(n), gcd(e, φ(n)) = 1  (often e = 65537) 

- Compute d: d × e ≡ 1 (mod φ(n))  → modular inverse 

- Public key = (n, e)  |  Private key = (n, d) 

Encrypt / Decrypt **Encrypt:** `C = M mod n ᵉ` **Decrypt:** `M = C mod n ᵈ` Digital Signature (RSA) **Sign:** `S = hash(M) mod n   [sign with private key] ᵈ` **Verify:** `hash(M) == S mod n  [verify with public key] ᵉ` 

### 3.2  ElGamal Encryption 

#### Key Generation 

- Choose large prime p and generator g 

- Choose private key x: 1 ≤ x ≤ p−2 

- Compute y = gˣ mod p 

- Public key = (p, g, y)  |  Private key = x 

#### Encrypt 

- Choose random k: 1 ≤ k ≤ p−2 

- c₁ = gᵏ mod p 

- c₂ = M × yᵏ mod p 

- Ciphertext = (c₁, c₂) 

#### Decrypt 

- s = c₁ˣ mod p 

- M = c₂ × s⁻¹ mod p   [s⁻¹ is modular inverse of s mod p] 

### 3.3  ECC – Elliptic Curve Cryptography 

**Curve:** `y² = x³ + ax + b (mod p)` 

- Private key: random integer d 

● Public key: Q = d × G  [point multiplication on curve] **Security basis:** ECDLP – given Q and G, finding d is computationally infeasible. **Common curves:** secp256k1, secp256r1 (P-256), P-384 **Advantage:** 256-bit ECC ≈ 3072-bit RSA in security strength. Much smaller keys. 

### 3.4  Diffie-Hellman Key Exchange 

- Public parameters: prime p, generator g 

- Alice: private a → sends A = gᵃ mod p 

- Bob:   private b → sends B = gᵇ mod p 

- Shared secret: K = Aᵇ mod p = Bᵃ mod p = gᵃᵇ mod p 

**Note:** DH is NOT encryption – it establishes a shared secret over an insecure channel. 

LAB 4 – Advanced Asymmetric + Key Management + Access Control 

### 4.1  Rabin Cryptosystem 

Key Generation 

- Choose large primes p and q where p ≡ q ≡ 3 (mod 4) 

- n = p × q  (public key)  |  (p, q) = private key 

#### Encrypt 

##### **C = M² mod n** 

Decrypt  [4 possible square roots → padding used to identify correct M] 

- m = c^((p+1)/4) mod pₚ 

- m_q = c^((q+1)/4) mod q 

- Use extended Euclidean to find yₚ, y_q: yₚp + y_qn = 1 

- r₁ = (yₚ×p×m_q + y_q×q×mₚ) mod n 

   - ₚ×p×m_q + y_q×q×mₚ) mod n 

- r₂ = n − r₁;  r₃ = (yₚ×p×m_q − y_q×q×mₚ) mod n;  r₄ = n − r₃ 

      - ₚ×p×m_q − y_q×q×mₚ) mod n;  r₄ = n − r₃ 

- One of {r₁,r₂,r₃,r₄} is the original plaintext (select via padding/checksum) 

**Security basis:** Factoring n is as hard as breaking Rabin. 

### 4.2  Key Management Concepts 

|**Concept**|**Formula / Definition**|
|---|---|
|Key Entropy|H(K) = −Σ p(i) × log₂(p(i))  [Shannon entropy]|
|Key Derivation|DK = KDF(Key, Salt, Iterations)  e.g. PBKDF2, scrypt, bcrypt|
|Key Rotation Rate|N / T  where N=number of keys, T=rotation period|
|Key Expiry|Expiry = t₀ + Lifetime|
|DH Shared Secret|K = gᵃᵇ mod p  (symmetric result from asymmetric exchange)|



### 4.3  ACCESS CONTROL MODELS  ← EXAM FOCUS 

#### RBAC – Role-Based Access Control 

**Formula:** `Access(User,Object) = Role: HasRole(User,Role)` ∃ ∧ `CanAccess(Role,Object)` 

Users are assigned roles. Roles have permissions. Users get permissions via roles. 

**Implementation:** `ACCESS = { "admin": {"read","write","delete"}, "user": {"read"} }` 

If exam changes roles: just change the dict keys and permission sets. 

#### ABAC – Attribute-Based Access Control 

**Formula:** `Access(User,Object,Env) = f(UserAttr, ObjectAttr, EnvAttr)` Access depends on attributes (department, clearance, time, location) rather than fixed roles. 

- User attributes: department="finance", clearance=3 

- Object attributes: classification=2, owner="alice" 

- Policy function f() evaluates combination → True/False 

#### Bell-LaPadula Model (Confidentiality – Military) 

**Simple Security:** `Subject level ≥ Object level  [No Read Up]` 

**★-Property:** `Subject level ≤ Object level  [No Write Down]` 

Levels: Unclassified < Confidential < Secret < Top Secret 

#### MAC – Mandatory Access Control 

**Formula:** `Access = (SubjectClearance ≥ ObjectClassification)` ∧ `PolicySatisfied` 

System-enforced labels. Users cannot change access rights. Used in SELinux, government systems. 

#### DAC – Discretionary Access Control 

**Formula:** `AccessMatrix[Subject][Object] = {Rights}  e.g. {read, write, execute}` 

Owner controls access to their own objects. Unix file permissions are DAC. 

#### Time-Based Access Control 

**Formula:** `Access(User,Object,Time) = (StartTime ≤ Time ≤ EndTime)` ∧ `OtherConditions` 

Grant access only during certain windows. Useful for shift-based systems. 

#### Probabilistic Access Control 

**Formula:** `P(Access | Conditions) = f(TrustLevel, Sensitivity, Risk)` Access granted based on probability threshold, not binary. Used in risk-adaptive systems. 

|**Model**|**Key Idea**|**Who controls?**|**Typical use**|
|---|---|---|---|
|RBAC|Access via Roles|Admin assigns roles|Enterprise apps, EduSecure|
|ABAC|Access via Attributes|Policy engine|Cloud IAM, zero-trust|
|Bell-LaPadula|No Read Up/No Write<br>Down|System/OS|Military, classified docs|
|MAC|Mandatory labels|System|SELinux, government|
|DAC|Owner decides|Data owner|Unix files, DRM|
|Time-based|Time windows|Admin|Shift workers, kiosks|



## LAB 5 – Hashing 

### 5.1  Properties of Cryptographic Hash Functions 

- Pre-image resistance (one-way): given h, hard to find M where H(M)=h 

- Second pre-image resistance: given M₁, hard to find M₂ where H(M₁)=H(M₂) 

- Collision resistance: hard to find any (M₁,M₂) pair where H(M₁)=H(M₂) 

### 5.2  Hash Algorithms at a Glance 

|**Algorithm**|**Output size**|**Block size**|**Status**|
|---|---|---|---|
|MD5|128 bits (32 hex)|512 bits|Broken – collisions found; avoid for<br>security|
|SHA-1|160 bits (40 hex)|512 bits|Deprecated – collisions found 2017|
|SHA-256|256 bits (64 hex)|512 bits|Secure – current standard (SHA-2 family)|
|SHA-512|512 bits (128 hex)|1024 bits|Secure – stronger variant|
|SHA-3/Keccak|224/256/384/512|Variable|Newest standard; sponge construction|
|Custom DJB2|32 bits|N/A|Lab exercise: seed=5381, ×33+ASCII, 32-<br>bit mask|



### 5.3  Custom DJB2 Hash (Lab Exercise 1) 

##### **Algorithm:** 

- Start: hash = 5381 

- For each char c in string: hash = ((hash << 5) + hash) + ord(c)  [i.e. hash*33 + ord(c)] 

- Apply 32-bit mask: hash = hash & 0xFFFFFFFF 

- Return hash as unsigned 32-bit integer 

## LAB 6 – Digital Signatures 

### 6.1  RSA Digital Signature 

- Signer computes hash of message: h = H(M) 

- Signs: S = hᵈ mod n   [uses private key d] 

- Verifier: h' = Sᵉ mod n   [uses public key e] 

- Valid if H(M) == h' 

### 6.2  ElGamal Signature (Schnorr variant) 

- Private: x;  Public: y = gˣ mod p 

- Sign: choose random k; r = gᵏ mod p; s = k⁻¹(H(M) − x×r) mod (p−1) 

- Signature = (r, s) 

- Verify: gᴴ⁽ᴹ⁾ ≡ yʳ × rˢ (mod p) 

### 6.3  CIA Triad via Cryptography 

|**Property**|**Technique**|**How**|
|---|---|---|
|Confidentiality (C)|Encryption (AES/DES/RSA)|Only intended receiver can read|
|Integrity (I)|Hashing (SHA-256)|Hash stored at send; recomputed at receive;|



|||mismatch = tampered|
|---|---|---|
|Authenticity (A)|Digital Signature (RSA)|Signature proves identity of sender|



### 6.4  Diffie-Hellman Key Exchange (also Lab 3) 

- Not encryption – establishes shared secret for subsequent symmetric encryption 

- Alice: a (private), A = gᵃ mod p (send to Bob) 

- Bob:   b (private), B = gᵇ mod p (send to Alice) 

- Shared secret: Alice computes Bᵃ mod p; Bob computes Aᵇ mod p → same value 

## QUICK SWAP REFERENCE  (for exam substitutions) 

|**If exam asks for...**|**Replace function**|**Key change**|**Import needed**|
|---|---|---|---|
|AES instead of DES|des_encrypt/decrypt|key = 16/24/32 bytes|from Crypto.Cipher<br>import AES|
|3DES instead of DES|des_encrypt/decrypt|key = 16 or 24 bytes|from Crypto.Cipher<br>import DES3|
|AES-CBC mode|des_encrypt/decrypt|add iv=os.urandom(16)|AES.MODE_CBC|
|AES-CTR mode|des_encrypt/decrypt|nonce + counter|AES.MODE_CTR|
|SHA-1 hash|compute_hash|hashlib.sha1()|import hashlib|
|MD5 hash|compute_hash|hashlib.md5()|import hashlib|
|ElGamal sign|rsa_sign/verify|generate p,g,x,y|from<br>Crypto.PublicKey<br>import ElGamal|
|ECC sign (ECDSA)|rsa_sign/verify|curve secp256r1|from<br>Crypto.PublicKey<br>import ECC|
|Rabin encrypt|des_encrypt/decrypt|C = M² mod n|sympy for Chinese<br>Remainder|
|ABAC instead of RBAC|check_access()|change ACCESS dict logic|no new import|
|Time-based access|check_access()|add datetime comparison|import datetime|



