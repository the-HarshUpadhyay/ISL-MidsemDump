**Subject: Information Security Lab (ICT 3141) Semester & Branch: 5**<sup>**th**</sup> **Sem, CCE A2 – Lab Mid-Term Exam min** 

**Date: 25-09-2025 Duration: (60+10)** 

**Roll No:** 



**Name:** 

**Reg. No:** 

## **Question:** 

You are tasked with developing a secure education data management system called EduSecure. This system ensures that students’ academic records are stored confidentially, accessed only by authorized users, and verified for authenticity. The system supports three types of users: Students, Faculties, and HoDs, each with specific roles and permissions. 

The platform uses **DES** symmetric encryption for storing sensitive academic records, **RSA** digital signatures for authenticating users, and **SHA-256** hashing to verify record integrity. 

# **_<u>User Roles & Permissions</u>_** 

## **Student:** 

- Encrypts a student’s academic records (for example: - ISL-5CCE-A2.txt) using **DES** before uploading. 

- Signs the **SHA-256** hash of the encrypted record using his/her **RSA** private key. 

- Can view past uploaded records and his/her encrypted/hashed forms with timestamps. 

## **Faculty:** 

- Decrypts the student’s records using the shared DES key. 

- Verifies RSA signatures of the students to ensure authenticity. 

- Computes SHA-256 hash of decrypted records and compares with the stored hash. 

- Stores verification results with timestamps. 

## **HoD:** 

- Can view only the hashed academic records with timestamps. 

- Verifies RSA signatures on stored records for accreditation purposes. 

## **Access Roles:** 

- Allow Students to encrypt records with DES, sign using RSA, and upload securely. 

- Enable Faculties to decrypt with DES, verify RSA signatures, and hash the records. 

- Allow HoDs to view only hashes and verify signatures. 

## **Task:** 

Develop a menu-driven Python program that implements these functionalities using: 

- DES symmetric encryption, 

- RSA digital signatures, and 

- SHA-256 hashing. 

Ensure secure handling of academic records and proper role-based access. Use any file or database structure to store and retrieve the records securely. 

||**Writ**|**eup**|||**Executi**|**on**||
|---|---|---|---|---|---|---|---|
|**Encryption**<br>**Decryption**<br>**(2 Marks)**|**Digital**<br>**Signatures**<br>**(1 Mark)**|**Access**<br>**Control**<br>**(1 Mark)**|**Hashing (1**<br>**Mark)**|**Encryption**<br>**Decryption**<br>**(6 Marks)**|**Digital**<br>**Signatures**<br>**(3 Marks)**|**Access**<br>**Control**<br>**(3**<br>**Marks)**|**Hashing**<br>**(3 Marks)**|
|**Remarks:**||||||||



