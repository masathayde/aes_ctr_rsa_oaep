def add_padding_PKCS_16Bytes(data: bytes) -> bytes:
    padding_length = 16 - len(data) % 16
    padding_byte = int.to_bytes(padding_length, 1, 'big')
    return data + padding_byte * padding_length

def remove_padding_PKCS_16Bytes(data: bytes) -> bytes:
    assert len(data) % 16 == 0
    padding_length = data[-1]
    for i in range(padding_length):
        assert data[-(i+1)] == padding_length
    return data[:-padding_length]