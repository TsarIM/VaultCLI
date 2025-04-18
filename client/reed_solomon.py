import reedsolo  # type: ignore

class ReedSolomonCodec:
    def __init__(self, data_chunks=10, parity_chunks=4):
        self.data_chunks = data_chunks
        self.parity_chunks = parity_chunks
        self.total_chunks = data_chunks + parity_chunks
        self.rs = reedsolo.RSCodec(parity_chunks)
    
    def encode(self, chunks):
        """
        Encode data chunks to generate parity chunks using Reed-Solomon.
        
        Args:
            chunks: List of bytearrays representing data chunks
            
        Returns:
            List of bytearrays representing parity chunks
        """
        if len(chunks) != self.data_chunks:
            raise ValueError(f"Expected {self.data_chunks} data chunks, got {len(chunks)}")
        
        chunk_size = len(chunks[0])
        parity_chunks = [bytearray(chunk_size) for _ in range(self.parity_chunks)]
        
        # Encode column-wise
        for k in range(chunk_size):
            column = bytes(chunk[k] for chunk in chunks)
            encoded = self.rs.encode(column)
            for i in range(self.parity_chunks):
                parity_chunks[i][k] = encoded[self.data_chunks + i]
        
        return parity_chunks
    
    def decode(self, chunks, indices):
        """
        Decode chunks to recover missing data.
        
        Args:
            chunks: List of available chunks (both data and parity)
            indices: List of indices of the available chunks
            
        Returns:
            List of all reconstructed data chunks
        """
        if len(chunks) < self.data_chunks:
            raise ValueError(f"Need at least {self.data_chunks} chunks for reconstruction, got {len(chunks)}")
        
        chunk_size = len(chunks[0])
        reconstructed = [bytearray(chunk_size) for _ in range(self.data_chunks)]
        
        # Which chunks are missing
        missing_indices = [i for i in range(self.data_chunks) if i not in indices[:self.data_chunks]]
        
        # If no chunks are missing from the data chunks, return them directly
        if not missing_indices:
            for i, idx in enumerate(indices[:self.data_chunks]):
                reconstructed[idx] = chunks[i]
            return reconstructed
        
        # Reconstruct column-wise
        for k in range(chunk_size):
            column = bytearray(self.total_chunks)
            erasure_positions = []
            
            # Fill known positions
            for i, idx in enumerate(indices):
                column[idx] = chunks[i][k]
            
            # Mark erasures
            for i in range(self.total_chunks):
                if i not in indices:
                    erasure_positions.append(i)
            
            # Decode with erasures
            decoded = self.rs.decode(column, erase_pos=erasure_positions)[0]
            
            # Fill reconstructed data chunks
            for i in range(self.data_chunks):
                reconstructed[i][k] = decoded[i]
        
        return reconstructed