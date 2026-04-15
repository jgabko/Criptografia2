import os
import base64
import hashlib

# =====================================================================
# PARTE 1: NÚCLEO MATEMÁTICO AES-256 (AES CORE)
# O algoritmo AES transforma blocos de 16 bytes em ruído indecifrável 
# utilizando as propriedades de Confusão e Difusão de Claude Shannon.
# =====================================================================

# 1.1: Tabelas de Confusão (S-Box)
# A S-BOX esconde a relação algébrica entre o dado e a chave.
# É calculada através do inverso multiplicativo no Campo de Galois GF(2^8).
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

# Tabela de espelho para a descriptografia.
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# RCON: Constantes que evitam simetrias na hora de quebrar a chave original em chaves menores.
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]

# 1.2 Matemática de Campo de Galois GF(2^8)
def galois_multiply(a, b):
    """
    Realiza a multiplicação polinomial em que cada byte é tratado como um polinômio de x.
    Sempre que o grau passar de 7 (maior que 255), ocorre redução via XOR com o polinômio 0x11B.
    """
    p = 0
    for _ in range(8):
        if b & 1: 
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11B
        b >>= 1
    return p % 256

def mix_single_column(c):
    """Mistura uma coluna usando a matriz fixa do AES na ida."""
    c0, c1, c2, c3 = c[0], c[1], c[2], c[3]
    r0 = galois_multiply(c0, 2) ^ galois_multiply(c1, 3) ^ c2 ^ c3
    r1 = c0 ^ galois_multiply(c1, 2) ^ galois_multiply(c2, 3) ^ c3
    r2 = c0 ^ c1 ^ galois_multiply(c2, 2) ^ galois_multiply(c3, 3)
    r3 = galois_multiply(c0, 3) ^ c1 ^ c2 ^ galois_multiply(c3, 2)
    return [r0, r1, r2, r3]

def inv_mix_single_column(c):
    """Mistura reversa da coluna usando a matriz inversa do AES na volta."""
    c0, c1, c2, c3 = c[0], c[1], c[2], c[3]
    r0 = galois_multiply(c0, 0x0e) ^ galois_multiply(c1, 0x0b) ^ galois_multiply(c2, 0x0d) ^ galois_multiply(c3, 0x09)
    r1 = galois_multiply(c0, 0x09) ^ galois_multiply(c1, 0x0e) ^ galois_multiply(c2, 0x0b) ^ galois_multiply(c3, 0x0d)
    r2 = galois_multiply(c0, 0x0d) ^ galois_multiply(c1, 0x09) ^ galois_multiply(c2, 0x0e) ^ galois_multiply(c3, 0x0b)
    r3 = galois_multiply(c0, 0x0b) ^ galois_multiply(c1, 0x0d) ^ galois_multiply(c2, 0x09) ^ galois_multiply(c3, 0x0e)
    return [r0, r1, r2, r3]

# 1.3 As Transformações de Rodada (The Rounds)
def sub_bytes(state, is_inv=False):
    """Toca cada byte da matriz de estado com a Tabela de Substituição (SBOX)."""
    box = INV_SBOX if is_inv else SBOX
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] = box[state[i][j]]
    return state

def shift_rows(state, is_inv=False):
    """Gira os bytes horizontalmente. A primeira linha não se move, a segunda move 1, etc."""
    for r in range(1, 4):
        row = [state[c][r] for c in range(4)]
        if not is_inv:
            shifted = row[r:] + row[:r]
        else:
            shifted = row[-r:] + row[:-r]
        for c in range(4):
            state[c][r] = shifted[c]
    return state

def mix_columns(state, is_inv=False):
    """Aplica a mistura vetorial (difusão) coluna por coluna."""
    for c in range(4):
        col = state[c]
        if not is_inv:
            state[c] = mix_single_column(col)
        else:
            state[c] = inv_mix_single_column(col)
    return state

def add_round_key(state, round_key):
    """Tranca o estado atual aplicando XOR com a chave daquela rodada."""
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_key[c][r]
    return state

# 1.4 Expansão da Chave (AES-256)
def expand_key(key):
    """
    Expande a chave mestra de 32 bytes em 15 matrizes 4x4 (Round Keys).
    Cada matriz servirá de cadeado para uma rodada diferente.
    """
    Nk, Nr = 8, 14
    words = []
    for i in range(Nk):
        word = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
        words.append(word)

    for i in range(Nk, 4 * (Nr + 1)):
        temp = words[i - 1][:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // Nk]
        elif i % Nk == 4:
            temp = [SBOX[b] for b in temp]

        word_m_nk = words[i - Nk]
        new_word = [word_m_nk[j] ^ temp[j] for j in range(4)]
        words.append(new_word)

    round_keys = []
    for i in range(Nr + 1):
        rk = [words[4*i], words[4*i+1], words[4*i+2], words[4*i+3]]
        round_keys.append(rk)
    return round_keys

# 1.5 Controle de Estado do Bloco
def bytes_to_state(data):
    """Organiza 16 bytes puros em uma matriz 4x4 preenchida por colunas."""
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[c][r] = data[r + 4*c]
    return state

def state_to_bytes(state):
    """Achata a matriz 4x4 de volta para uma linha de 16 bytes."""
    res = bytearray(16)
    for r in range(4):
        for c in range(4):
            res[r + 4*c] = state[c][r]
    return bytes(res)

def encrypt_block(block, expanded_keys):
    """Manda 1 bloco de 16 bytes para o liquidificador matemático do AES."""
    state = bytes_to_state(block)
    state = add_round_key(state, expanded_keys[0])
    for round_num in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded_keys[round_num])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_keys[14])
    return state_to_bytes(state)

def decrypt_block(block, expanded_keys):
    """Tira o bloco de 16 bytes do liquidificador (Operações reversas na ordem inversa)."""
    state = bytes_to_state(block)
    state = add_round_key(state, expanded_keys[14])
    state = shift_rows(state, is_inv=True)
    state = sub_bytes(state, is_inv=True)
    for round_num in range(13, 0, -1):
        state = add_round_key(state, expanded_keys[round_num])
        state = mix_columns(state, is_inv=True)
        state = shift_rows(state, is_inv=True)
        state = sub_bytes(state, is_inv=True)
    state = add_round_key(state, expanded_keys[0])
    return state_to_bytes(state)


# =====================================================================
# PARTE 2: PBKDF2, PADDING E MANIPULAÇÃO (A ATIVIDADE PRÁTICA)
# =====================================================================

def derivar_chave_pbkdf2(senha_str, salt_bytes):
    """
    Pega uma senha insegura de usuário e um 'tempero' (salt) aleatório.
    Roda um Hash SHA-256 cem mil vezes sobre a senha.
    Isso pune atacantes de força-bruta e gera nossa chave perfeita de 32 bytes para o AES-256.
    """
    chave = hashlib.pbkdf2_hmac(
        'sha256', 
        senha_str.encode('utf-8'), 
        salt_bytes, 
        100000, 
        32
    )
    return chave

def aplicar_padding(dados_bytes):
    """
    O AES é engessado: só mastiga blocos cravados de 16 bytes.
    Se temos 19 bytes de texto, precisamos encher 13 bytes com o valor "13" (0x0D).
    Isso é o protocolo PKCS#7.
    """
    pad_len = 16 - (len(dados_bytes) % 16)
    return dados_bytes + bytes([pad_len] * pad_len)

def remover_padding(dados_bytes):
    """
    Lê a marca d'água final de padding (ex: descobre que foram 13 bytes inseridos)
    e recorta esses bytes falsos para restaurar o texto com exatidão.
    """
    pad_len = dados_bytes[-1]
    return dados_bytes[:-pad_len]

def encriptar_texto(texto, senha):
    """
    ATIVIDADE 1.1: Recebe texto e senha, cospe o criptograma seguro Base64.
    """
    # 1. Gera um código dinâmico exclusivo (Salt) de 16 bytes. 
    # Isso torna a chave diferente mesmo que a senha "123" seja usada duas vezes.
    salt = os.urandom(16)
    
    # 2. Chama a derivação pesada para forjar a chave, e depois a expande pro AES.
    chave_256 = derivar_chave_pbkdf2(senha, salt)
    chaves_expandidas = expand_key(chave_256)
    
    # 3. Transforma o texto legível em bytes puros e arredonda para fechar blocos de 16.
    texto_bytes = texto.encode('utf-8')
    dados_preparados = aplicar_padding(texto_bytes)
    
    # 4. Modo de Operação ECB: Corta a mensagem em fatias e joga no AES.
    ciphertext = bytearray()
    for i in range(0, len(dados_preparados), 16):
        bloco = dados_preparados[i:i+16]
        bloco_cifrado = encrypt_block(bloco, chaves_expandidas)
        ciphertext.extend(bloco_cifrado)
        
    # 5. O PBKDF2 precisa do Salt para destrancar no futuro, então anexamos ele na frente.
    # Em seguida, embrulhamos em Base64 para que os bytes selvagens virem caracteres de texto normais.
    resultado_final = salt + ciphertext
    return base64.b64encode(resultado_final).decode('utf-8')

def desencriptar_texto(texto_cifrado_b64, senha):
    """
    ATIVIDADE 1.2: Recebe o Base64 e a senha, destranca e entrega o texto.
    """
    try:
        # 1. Desfaz a codificação de texto amigável de volta para bytes feios e aleatórios.
        dados_completos = base64.b64decode(texto_cifrado_b64)
    except Exception:
        return "ERRO: Base64 corrompido."
        
    # 2. Resgata o Salt original que foi anexado na frente.
    # Nós sabemos com 100% de certeza que o Salt foi configurado com tamanho de 16 bytes.
    salt = dados_completos[:16]
    ciphertext = dados_completos[16:]
    
    # 3. Tenta recriar a Chave Mestra usando a Senha digitada + O Salt resgatado.
    # Se o usuário errar 1 letra da senha, a chave forjada aqui será um lixo inútil.
    chave_256 = derivar_chave_pbkdf2(senha, salt)
    chaves_expandidas = expand_key(chave_256)
    
    # 4. Joga as fatias de 16 bytes da cifra de trás pra frente no AES (Decrypt).
    texto_com_padding = bytearray()
    try:
        for i in range(0, len(ciphertext), 16):
            bloco = ciphertext[i:i+16]
            bloco_decifrado = decrypt_block(bloco, chaves_expandidas)
            texto_com_padding.extend(bloco_decifrado)
            
        # 5. Corta o lixo de preenchimento inserido anteriormente.
        texto_bytes_puros = remover_padding(texto_com_padding)
        # O último teste de fogo: Tenta decodificar para linguagem humana.
        # Se a chave era errada, isso aqui vai bugar e cair no 'except', pois o texto gerado não fará sentido no UTF-8.
        return texto_bytes_puros.decode('utf-8')
    except Exception:
        return "ERRO: A senha está errada ou os dados de cifra foram atacados!"


# =====================================================================
# ÁREA DE EXECUÇÃO: O Teste Definitivo
# =====================================================================
if __name__ == "__main__":
    print("\n" + "="*50)
    print(" INICIANDO TESTE DO ALGORITMO AES MONOLÍTICO ")
    print("="*50)
    
    frase = "Mensagem confidencial. O servidor deve explodir as 14h."
    senha = "PamonhaSecreta99!"
    
    print(f"\n[TEXTO PLANO]: {frase}")
    print(f"[SENHA]: {senha}")
    
    # Executa a atividade 1.1
    cifra = encriptar_texto(frase, senha)
    print(f"\n[ENCRIPTADO] (Em Base64):\n{cifra}")
    
    # Executa a atividade 1.2
    decriptado = desencriptar_texto(cifra, senha)
    print(f"\n[DESENCRIPTADO] (Sucesso):\n{decriptado}")
    
    # Teste de Fallback (Cenário de ataque ou erro do usuário)
    print(f"\n[TESTANDO COM SENHA ERRADA 'PamonhaSecreta11!']:")
    erro = desencriptar_texto(cifra, "PamonhaSecreta11!")
    print(erro)
    print("="*50)