import os
import math
import hashlib
import random
import sympy
from typing import List, Tuple, Dict, Any
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class RSAHomomorphicTagSystem:
    
    def __init__(self, key_size=2048):
        # Generate RSA key pair
        self._generate_key_pair(key_size)
        
        # For homomorphic verification we need to know the modulus
        self.n = self.private_key.private_numbers().public_numbers.n
        self.e = self.private_key.private_numbers().public_numbers.e
        self.d = self.private_key.private_numbers().d
        
        # Generate random generators for each possible chunk
        # In a real implementation, these would be chosen more carefully
        self.max_chunks = 100  # Maximum number of chunks we'll support
        self.generators = []
        for _ in range(self.max_chunks):
            # Choose a random generator that's coprime to n
            while True:
                g = random.randint(2, self.n - 1)
                if math.gcd(g, self.n) == 1:
                    self.generators.append(g)
                    break
    
    def _generate_key_pair(self, key_size):

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def _hash_to_int(self, chunk: bytes) -> int:

        h = hashlib.sha256()
        h.update(chunk)
        digest = h.digest()
        return int.from_bytes(digest, byteorder='big') % self.n
    
    def generate_tag(self, chunk: bytes, chunk_id: int) -> int:
        
        if chunk_id >= self.max_chunks:
            raise ValueError(f"Chunk ID {chunk_id} exceeds maximum supported chunks")
        
        # Get hash of the chunk as an integer
        h_chunk = self._hash_to_int(chunk)
        
        # Get generator for this chunk
        g_i = self.generators[chunk_id]
        
        # Compute tag = (g_i^h(chunk_i))^d mod n
        # This is the RSA signing operation but using the generator and message hash
        # Note: For efficiency we compute modular exponentiation directly rather than using the RSA primitive
        tag = pow(g_i, h_chunk, self.n)
        tag = pow(tag, self.d, self.n)
        
        return tag
    
    def verify_tag(self, chunk: bytes, chunk_id: int, tag: int) -> bool:
        
        if chunk_id >= self.max_chunks:
            raise ValueError(f"Chunk ID {chunk_id} exceeds maximum supported chunks")
        
        # Get hash of the chunk as an integer
        h_chunk = self._hash_to_int(chunk)
        
        # Get generator for this chunk
        g_i = self.generators[chunk_id]
        
        # Compute g_i^h(chunk_i) mod n
        expected = pow(g_i, h_chunk, self.n)
        
        # Compute tag^e mod n
        tag_raised = pow(tag, self.e, self.n)
        
        # Verify that tag^e ≡ g_i^h(chunk_i) mod n
        return tag_raised == expected
    
    def aggregate_tags(self, tags: List[int], coefficients: List[int]) -> int:
        
        if len(tags) != len(coefficients):
            raise ValueError("Number of tags and coefficients must match")
        
        aggregate_tag = 1
        
        for tag, coef in zip(tags, coefficients):

            tag_raised = pow(tag, coef, self.n)

            aggregate_tag = (aggregate_tag * tag_raised) % self.n
        
        return aggregate_tag
    
    def verify_linear_combination(self, 
                                 chunks: List[bytes], 
                                 chunk_ids: List[int],
                                 coefficients: List[int], 
                                 aggregate_tag: int) -> bool:
        
        if not (len(chunks) == len(chunk_ids) == len(coefficients)):
            raise ValueError("Length of chunks, chunk IDs, and coefficients must match")
        
        expected = 1
        for chunk, chunk_id, coef in zip(chunks, chunk_ids, coefficients):

            h_chunk = self._hash_to_int(chunk)
            
            g_i = self.generators[chunk_id]
            
            component = pow(g_i, h_chunk, self.n)
            component = pow(component, coef, self.n)
            
            expected = (expected * component) % self.n
        
        tag_raised = pow(aggregate_tag, self.e, self.n)
        
        return tag_raised == expected


class DataIntegrityAuditor:
    
    def __init__(self, num_chunks=10):
        self.num_chunks = num_chunks
        self.rsa_tag_system = RSAHomomorphicTagSystem()
        
    def split_file(self, file_path: str) -> List[bytes]:
        file_size = os.path.getsize(file_path)
        chunk_size = math.ceil(file_size / self.num_chunks)
        
        chunks = []
        with open(file_path, 'rb') as f:
            for _ in range(self.num_chunks):
                chunk = f.read(chunk_size)
                if not chunk:  
                    break
                chunks.append(chunk)
        
        while len(chunks) < self.num_chunks:
            chunks.append(b'')
                
        return chunks
    
    def generate_proof(self, file_path: str) -> Dict[str, Any]:

        chunks = self.split_file(file_path)
        
        rsa_tags = []
        for i, chunk in enumerate(chunks):
            tag = self.rsa_tag_system.generate_tag(chunk, i)
            rsa_tags.append(tag)
        
        return {
            'file_path': file_path,
            'num_chunks': len(chunks),
            'rsa_tags': rsa_tags,
            'file_hash': hashlib.sha256(b''.join(chunks)).hexdigest(),
            'rsa_n': self.rsa_tag_system.n,
            'rsa_e': self.rsa_tag_system.e,
            'rsa_generators': self.rsa_tag_system.generators[:len(chunks)],
        }
    
    def verify_integrity(self, file_path: str, proof: Dict[str, Any]) -> bool:
        
        chunks = self.split_file(file_path)
        
        if len(chunks) != proof['num_chunks']:
            print("Number of chunks doesn't match")
            return False
        
        temp_rsa = RSAHomomorphicTagSystem()
        temp_rsa.n = proof['rsa_n']
        temp_rsa.e = proof['rsa_e']
        temp_rsa.generators = proof['rsa_generators']
        
        for i, chunk in enumerate(chunks):
            expected_tag = proof['rsa_tags'][i]
            
            h_chunk = temp_rsa._hash_to_int(chunk)
            g_i = temp_rsa.generators[i]
            expected = pow(g_i, h_chunk, temp_rsa.n)
            tag_raised = pow(expected_tag, temp_rsa.e, temp_rsa.n)
            
            if tag_raised != expected:
                print(f"RSA tag verification failed for chunk {i}")
                return False
        
        computed_hash = hashlib.sha256(b''.join(chunks)).hexdigest()
        if computed_hash != proof['file_hash']:
            print(f"File hash mismatch: {computed_hash} != {proof['file_hash']}")
            return False
            
        return True
    
    def audit_random_chunks(self, file_path: str, proof: Dict[str, Any], 
                           num_challenges: int = 3) -> bool:
        
        chunks = self.split_file(file_path)
        
        if len(chunks) != proof['num_chunks']:
            print("Number of chunks doesn't match during audit")
            return False
        
        challenge_indices = random.sample(range(len(chunks)), min(num_challenges, len(chunks)))
        
        coefficients = [random.randint(1, 100) for _ in range(len(challenge_indices))]
        
        temp_rsa = RSAHomomorphicTagSystem()
        temp_rsa.n = proof['rsa_n']
        temp_rsa.e = proof['rsa_e']
        temp_rsa.generators = proof['rsa_generators']
        
        challenged_chunks = [chunks[i] for i in challenge_indices]
        challenged_tags = [proof['rsa_tags'][i] for i in challenge_indices]
        
        aggregate_tag = temp_rsa.aggregate_tags(challenged_tags, coefficients)
        
        return temp_rsa.verify_linear_combination(
            challenged_chunks, challenge_indices, coefficients, aggregate_tag
        )


def demo_audit_system(file_path: str):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
        
    auditor = DataIntegrityAuditor(num_chunks=10)
    
    print(f"Generating proof for {file_path}...")
    proof = auditor.generate_proof(file_path)
    print()
    print(proof)
    print()
    print(f"Proof generated. File split into {proof['num_chunks']} chunks.")
    
    print("Verifying file integrity...")
    if auditor.verify_integrity(file_path, proof):
        print("File integrity verified successfully!")
    else:
        print("File integrity verification failed!")
    
    print("Performing random chunk audit with homomorphic verification...")
    if auditor.audit_random_chunks(file_path, proof, num_challenges=3):
        print("Random chunk audit passed using homomorphic properties!")
    else:
        print("Random chunk audit failed using homomorphic properties!")
    
    print("\nDemonstrating homomorphic property with two chunks:")
    chunks = auditor.split_file(file_path)
    if len(chunks) >= 2:
        chunk0, chunk1 = chunks[0], chunks[1]
        tag0, tag1 = proof['rsa_tags'][0], proof['rsa_tags'][1]
        
        temp_rsa = RSAHomomorphicTagSystem()
        temp_rsa.n = proof['rsa_n']
        temp_rsa.e = proof['rsa_e']
        temp_rsa.generators = proof['rsa_generators']
        
        coef0, coef1 = 3, 5  
        combined_tag = temp_rsa.aggregate_tags([tag0, tag1], [coef0, coef1])
        
        verification = temp_rsa.verify_linear_combination(
            [chunk0, chunk1], [0, 1], [coef0, coef1], combined_tag
        )
        
        if verification:
            print(f"Verified linear combination: {coef0}×chunk[0] + {coef1}×chunk[1]")
        else:
            print(f"Failed to verify linear combination")
    
    print("\nSimulating file tampering...")
    tampered_file = file_path + ".tampered"
    chunks = auditor.split_file(file_path)
    if chunks[0]:  
        if len(chunks[0]) > 8:
            chunks[0] = b'TAMPERED' + chunks[0][8:]  # Tamper first chunk
        else:
            chunks[0] = b'TAMPERED'
    
    with open(tampered_file, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)
    
    print("Verifying tampered file integrity...")
    if auditor.verify_integrity(tampered_file, proof):
        print("Tampered file incorrectly passed verification!")
    else:
        print("Tampered file correctly failed verification!")
    
    os.remove(tampered_file)


if __name__ == "__main__":

    import sys
    
    if len(sys.argv) != 2:
        print("Usage: hvt.py <file_path>")
        file_path = input("Enter the path to the file you want to audit: ")
    else:
        file_path = sys.argv[1]
    
    demo_audit_system(file_path)
