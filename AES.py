# =====================================================================
# 1. TABELAS DE LOOKUP (S-BOX e RCON)
# =====================================================================

# S-Box do AES pré-computada. Usada para a etapa de SubBytes e Key Expansion.
# Substitui cada byte por um novo valor, provendo a "confusão".
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Rcon (Round Constants). Usados na Key Expansion[cite: 255].
# Apenas o primeiro byte do Rcon varia; os demais são zeros[cite: 255].
RCON = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
]

# =====================================================================
# 2. FUNÇÕES BASE (SUBBYTES E SHIFT ROWS)
# =====================================================================

def sub_bytes(state):
    """
    SubBytes: Substitui cada byte do estado (State) usando a tabela S-BOX[cite: 141].
    O State é representado como uma lista de 4 listas (colunas), contendo 4 bytes cada.
    """
    for col in range(4):
        for row in range(4):
            # Obtém o valor atual e mapeia para a S-Box
            state[col][row] = SBOX[state[col][row]]
    return state

def shift_rows(state):
    """
    ShiftRows: Permutação onde as linhas do estado sofrem deslocamento circular à esquerda[cite: 143].
    - Linha 0: Desloca 0
    - Linha 1: Desloca 1
    - Linha 2: Desloca 2
    - Linha 3: Desloca 3[cite: 149].
    """
    # Note que nossa estrutura de state é state[col][row] (orientado a colunas).
    # Precisamos trabalhar nas linhas.
    for row in range(1, 4):
        # Extrai a linha inteira iterando pelas colunas
        current_row = [state[col][row] for col in range(4)]
        # Faz o deslocamento (shift) baseado no índice da linha
        shifted_row = current_row[row:] + current_row[:row]
        # Recoloca a linha deslocada na matriz de estado
        for col in range(4):
            state[col][row] = shifted_row[col]
    return state

# =====================================================================
# 3. MATEMÁTICA DE CORPOS DE GALOIS E MIX COLUMNS
# =====================================================================

def galois_multiply(a, b):
    """
    Multiplica dois números no Campo de Galois GF(2^8)[cite: 309, 310].
    Isso não é uma multiplicação aritmética padrão, mas a multiplicação de 
    polinômios com redução modular pelo polinômio irredutível do AES: 0x11B.
    """
    p = 0
    for _ in range(8):
        if b & 1:  # Se o bit mais à direita de 'b' for 1, adiciona 'a' ao resultado (XOR)
            p ^= a
        hi_bit_set = a & 0x80 # Verifica se o bit mais alto (x^7) de 'a' é 1
        a <<= 1
        # Se 'a' ultrapassar 8 bits (o bit mais alto era 1), faz o XOR com 0x11B
        if hi_bit_set:
            a ^= 0x11B
        b >>= 1 # Move o próximo bit de 'b' para a direita
    return p % 256 # Retorna os 8 bits mais baixos

def mix_columns(state):
    """
    MixColumns: Processa o estado coluna por coluna para prover "difusão"[cite: 138, 150].
    Multiplica cada coluna por uma matriz constante.
    """
    for col in range(4):
        c0 = state[col][0]
        c1 = state[col][1]
        c2 = state[col][2]
        c3 = state[col][3]
        
        # A matriz fixa do AES para a multiplicação é:
        # [2 3 1 1]
        # [1 2 3 1]
        # [1 1 2 3]
        # [3 1 1 2]
        # Multiplicações por 1 são apenas o valor original. Multiplicações por 2 ou 3 usam o Galois Field.
        state[col][0] = galois_multiply(c0, 2) ^ galois_multiply(c1, 3) ^ c2 ^ c3
        state[col][1] = c0 ^ galois_multiply(c1, 2) ^ galois_multiply(c2, 3) ^ c3
        state[col][2] = c0 ^ c1 ^ galois_multiply(c2, 2) ^ galois_multiply(c3, 3)
        state[col][3] = galois_multiply(c0, 3) ^ c1 ^ c2 ^ galois_multiply(c3, 2)
    return state

# =====================================================================
# 4. KEY DERIVATION / EXPANSION (AES-128 focado)
# =====================================================================

def rot_word(word):
    """
    RotWord: Pega uma palavra (4 bytes / 32 bits) e faz um deslocamento circular
    de 1 byte para a esquerda[cite: 252]. [b0, b1, b2, b3] vira [b1, b2, b3, b0].
    """
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

def sub_word(word):
    """
    SubWord: Pega uma palavra de 4 bytes e substitui cada byte usando a S-Box[cite: 253].
    """
    b0 = SBOX[(word >> 24) & 0xFF]
    b1 = SBOX[(word >> 16) & 0xFF]
    b2 = SBOX[(word >> 8) & 0xFF]
    b3 = SBOX[word & 0xFF]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

def key_expansion(key_bytes):
    """
    Key Derivation: Expande a chave original de 16 bytes (128 bits) em 
    44 palavras (Words) de 32 bits. Isso criará 11 "Round Keys" no total[cite: 232, 234].
    """
    words = [0] * 44 # 4 palavras por rodada * 11 rodadas = 44 palavras [cite: 242]
    
    # As primeiras 4 palavras são apenas a chave original preenchida
    for i in range(4):
        words[i] = (key_bytes[4*i] << 24) | (key_bytes[4*i + 1] << 16) | \
                   (key_bytes[4*i + 2] << 8) | key_bytes[4*i + 3]
                   
    # Expansão para as 40 palavras restantes
    for i in range(4, 44):
        temp = words[i - 1]
        
        # A cada 4 palavras (uma nova Round Key), aplicamos o G-Function (RotWord + SubWord + RCON)
        if i % 4 == 0:
            # temp passa por um RotWord, SubWord e é aplicado XOR com a constante RCON[cite: 252, 255].
            temp = sub_word(rot_word(temp)) ^ RCON[i // 4]
            
        # A nova palavra é um XOR da palavra de 4 posições atrás com o 'temp' manipulado [cite: 246]
        words[i] = words[i - 4] ^ temp
        
    return words

# =====================================================================
# EXEMPLO DE USO PARA TESTAR AS FUNÇÕES
# =====================================================================
if __name__ == "__main__":
    # 1. Testando a State Array e manipulações:
    # Representando uma state de 16 bytes (como matriz 4x4 baseada em colunas).
    # Este é um estado fictício só para testarmos a compilação das etapas.
    initial_state = [
        [0x19, 0xa0, 0x9a, 0xe9], # Coluna 0
        [0x3d, 0xf4, 0xc6, 0xf8], # Coluna 1
        [0xe3, 0xe2, 0x8d, 0x48], # Coluna 2
        [0xbe, 0x2b, 0x2a, 0x08]  # Coluna 3
    ]

    print("Estado Original (Colunas):")
    for c in initial_state: print([hex(x) for x in c])

    print("\n--- Aplicando SubBytes ---")
    state_sub = sub_bytes(initial_state)
    for c in state_sub: print([hex(x) for x in c])

    print("\n--- Aplicando ShiftRows ---")
    state_shift = shift_rows(state_sub)
    for c in state_shift: print([hex(x) for x in c])

    print("\n--- Aplicando MixColumns ---")
    state_mix = mix_columns(state_shift)
    for c in state_mix: print([hex(x) for x in c])

    print("\n--- Aplicando Key Derivation (Key Expansion) ---")
    # Chave teste de 16 bytes (128 bits)
    test_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    
    expanded_keys = key_expansion(test_key)
    print("Primeiras 8 Words (Palavras de 32 bits) da chave expandida:")
    for i in range(8):
        print(f"Word {i}: {hex(expanded_keys[i])}")