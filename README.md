# Enhancing Privacy in eKYC 


### Information preprocessing:


```python 
import hashlib
import struct

# Function to convert a string into 32-bit chunks
def string_to_chunks(data):
    # Convert each character to its ASCII value
    ascii_values = [ord(char) for char in data]
    
    # Pad the ASCII values with zeros to make the total length a multiple of 4
    while len(ascii_values) % 4 != 0:
        ascii_values.append(0)
    
    # Pack every 4 ASCII values into a 32-bit chunk
    chunks = [struct.unpack(">I", bytes(ascii_values[i:i+4]))[0] for i in range(0, len(ascii_values), 4)]
    
    return chunks

# Dynamically input eKYC information
fields = {
    "Full Name": input("Enter Full Name: "),
    "Date of Birth": input("Enter Date of Birth (YYYY-MM-DD): "),
    "Gender": input("Enter Gender: "),
    "Nationality": input("Enter Nationality: "),
    "National ID Number": input("Enter National ID Number: "),
    "Address": input("Enter Address: "),
    "Issue Date": input("Enter Issue Date (YYYY-MM-DD): "),
    "Expiry Date": input("Enter Expiry Date (YYYY-MM-DD): "),
    "Place of Birth": input("Enter Place of Birth: "),
    "Issuing Authority": input("Enter Issuing Authority: ")
}

# Selective Disclosure: Ask the user which fields to include
print("\nSelect which fields to include in the hash computation:")
selected_fields = []
selected_info = {}
for key in fields:
    include = input(f"Include {key}? (y/n): ").strip().lower()
    if include == 'y':
        selected_fields.append(fields[key])
        selected_info[key] = fields[key]

# Combine selected fields into a single string
ekyc_combined = ''.join(selected_fields)

# Print the selected eKYC information (keys only)
print("\n--- Selected eKYC Information ---")
for key in selected_info.keys():
    print(f"{key}")

# Convert the combined string to 32-bit chunks
ekyc_info_chunks = string_to_chunks(ekyc_combined)

# Ensure we have exactly 16 chunks (padded if necessary)
while len(ekyc_info_chunks) < 16:
    ekyc_info_chunks.append(0)

print("\n--- eKYC Info (16 x 32-bit chunks) ---")
for chunk in ekyc_info_chunks:
    print(f"0x{chunk:08x}")

# Convert the 32-bit chunks to bytes
ekyc_info_bytes = b''.join([struct.pack('>I', chunk) for chunk in ekyc_info_chunks])

# Compute the SHA-256 hash
hash_value = hashlib.sha256(ekyc_info_bytes).hexdigest()

# Convert the hash into 8 chunks of 32 bits
hash_chunks = [int(hash_value[i:i+8], 16) for i in range(0, len(hash_value), 8)]

print("\n--- Expected Hash (8 x 32-bit integers) ---")
for chunk in hash_chunks:
    print(f"0x{chunk:08x}")

```
### Information preprocessing Output:

![image](https://github.com/user-attachments/assets/9432f6fb-14ab-4757-ab18-33f95e19032b)

![image](https://github.com/user-attachments/assets/083d96f8-a2b8-4d62-a793-6614b75f96a2)

### Smart contract to generate proof:
```solidity 
import "hashes/sha256/512bit" as sha256;

// The main function for proving eKYC information
def main() -> bool {
   
    
    // Padding the remaining chunks with zeros to fill the 512-bit requirement
    u32[16] eKYC_info = [
        0x4a6f686e, 0x4d616c65, 0x4a617061, 0x34002e00, 0x6e000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ];
    u32[8] expected_hash = [
        0x726dd5a5, 0xabc4f8a7, 0xc38b6b54, 0x5ef62227,
        0x2fc076ea, 0xa7250548, 0x949c546f, 0x31a8a816
    ];
    u32[8] computed_hash = sha256(eKYC_info[0..8], eKYC_info[8..16]);
    bool isValid = computed_hash == expected_hash;
    return isValid;
}
```
