# aes_core.py
# NÚCLEO CRIPTOGRÁFICO AES-256 PURAMENTE PROCEDURAL E MATEMÁTICO

# =====================================================================
# 1. TABELAS DE SUBSTITUIÇÃO (LOOKUP TABLES) E CONSTANTES
# =====================================================================

# S-BOX (Substitution Box)
# Conceito: A S-BOX é o coração da propriedade de "Confusão" estipulada por Claude Shannon.
# Seu objetivo é esconder qualquer relação algébrica simples entre a chave, o texto plano 
# e o texto cifrado. Se alterarmos 1 bit na entrada, a saída muda de forma drástica e não-linear.
# Como foi gerada? Não é aleatória. Para cada byte (0x00 a 0xFF), os matemáticos calcularam
# o seu "inverso multiplicativo" no Corpo de Galois GF(2^8) e aplicaram uma transformação afim.
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

# INVERSE S-BOX: Tabela de espelho.
# Se durante a encriptação o byte 0x00 virou 0x63, na descriptografia precisamos
# que o 0x63 vire 0x00. Esta tabela é simplesmente a matriz inversa da S-Box acima.
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

# RCON (Round Constants)
# Utilizado EXCLUSIVAMENTE na expansão de chaves (Key Schedule).
# Para evitar que as "chaves de rodada" tenham simetria (o que facilitaria ataques),
# nós injetamos o RCON nelas. Note que apenas o primeiro byte (potências de x em Galois) muda.
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]

# =====================================================================
# 2. MATEMÁTICA DE CORPOS DE GALOIS E MIX COLUMNS
# =====================================================================

def galois_multiply(a, b):
    """
    Multiplicação em GF(2^8).
    Por que usar Galois? Se multiplicarmos números binários normais (ex: 200 * 2),
    o resultado é 400. Porém, 400 não cabe em 1 byte (limite é 255). 
    A matemática de Galois é um "universo fechado" onde qualquer operação entre dois
    bytes sempre resulta em um byte.
    """
    # 'p' armazenará o resultado da multiplicação. Inicia em 0.
    p = 0
    # O loop roda 8 vezes (uma para cada bit de um byte).
    for _ in range(8):
        # Passo 1: Adição (via XOR). 
        # Se o bit mais à direita de 'b' for 1, nós somamos 'a' em 'p'.
        # No Corpo de Galois, a adição de polinômios é perfeitamente representada por XOR (^).
        if b & 1: 
            p ^= a
            
        # Passo 2: Verificamos se 'a' está prestes a "transbordar" (ultrapassar 8 bits).
        # Fazemos isso checando se o bit mais à esquerda (0x80 = 10000000) é 1.
        hi_bit_set = a & 0x80
        
        # Passo 3: Deslocamento (Multiplicação por x).
        # Movemos todos os bits de 'a' uma casa para a esquerda (a <<= 1).
        a <<= 1
        
        # Passo 4: Redução Modular.
        # Se aquele bit alto era 1, nosso deslocamento acima fez o número passar de 255.
        # Para trazê-lo de volta ao universo de 1 byte, subtraímos (via XOR) o 
        # polinômio irredutível fixo do AES: 0x11B (x^8 + x^4 + x^3 + x + 1).
        if hi_bit_set:
            a ^= 0x11B
            
        # Passo 5: Prepara o próximo bit de 'b' movendo-o para a direita.
        b >>= 1
        
    # Garante estruturalmente que nada vaze além de 255 (8 bits).
    return p % 256

def mix_single_column(c):
    """
    Aplica MixColumns a uma coluna vertical de 4 bytes.
    A propriedade de "Difusão" (onde 1 bit alterado se espalha para vários bits)
    ocorre fortemente aqui. O novo valor do byte 1 dependerá dos valores antigos dos bytes 1, 2, 3 e 4.
    """
    # Extrai os 4 bytes da coluna fornecida.
    c0, c1, c2, c3 = c[0], c[1], c[2], c[3]
    
    # Multiplica a coluna pela matriz fixa do AES:
    # [2 3 1 1]
    # [1 2 3 1]
    # [1 1 2 3]
    # [3 1 1 2]
    # Obs: Multiplicar por 1 em Galois retorna o próprio número (c0, c1, etc).
    # Multiplicar por 2 e 3 exige a nossa função galois_multiply.
    # O sinal ^ (XOR) está somando os resultados para gerar o novo byte.
    r0 = galois_multiply(c0, 2) ^ galois_multiply(c1, 3) ^ c2 ^ c3
    r1 = c0 ^ galois_multiply(c1, 2) ^ galois_multiply(c2, 3) ^ c3
    r2 = c0 ^ c1 ^ galois_multiply(c2, 2) ^ galois_multiply(c3, 3)
    r3 = galois_multiply(c0, 3) ^ c1 ^ c2 ^ galois_multiply(c3, 2)
    return [r0, r1, r2, r3]

def inv_mix_single_column(c):
    """
    Desfaz a mistura de colunas. Como a matriz fixa original usava os números {1, 2, 3},
    sua matriz inversa matemática é mais complexa, usando {9, 11, 13, 14} (ou 0x09, 0x0b, 0x0d, 0x0e).
    """
    c0, c1, c2, c3 = c[0], c[1], c[2], c[3]
    # A lógica é a mesma, mas com constantes galois maiores.
    r0 = galois_multiply(c0, 0x0e) ^ galois_multiply(c1, 0x0b) ^ galois_multiply(c2, 0x0d) ^ galois_multiply(c3, 0x09)
    r1 = galois_multiply(c0, 0x09) ^ galois_multiply(c1, 0x0e) ^ galois_multiply(c2, 0x0b) ^ galois_multiply(c3, 0x0d)
    r2 = galois_multiply(c0, 0x0d) ^ galois_multiply(c1, 0x09) ^ galois_multiply(c2, 0x0e) ^ galois_multiply(c3, 0x0b)
    r3 = galois_multiply(c0, 0x0b) ^ galois_multiply(c1, 0x0d) ^ galois_multiply(c2, 0x09) ^ galois_multiply(c3, 0x0e)
    return [r0, r1, r2, r3]

# =====================================================================
# 3. AS QUATRO TRANSFORMAÇÕES DE RODADA (THE ROUNDS)
# =====================================================================
# O AES organiza o bloco de 16 bytes como uma grade 4x4 chamada "Matriz de Estado".

def sub_bytes(state, is_inv=False):
    """
    Passo 1/4 da Rodada: Substituição de Bytes.
    Toca em cada um dos 16 bytes do estado atual e os substitui utilizando a S-BOX.
    """
    # Decide qual tabela usar dependendo de estarmos encriptando ou descriptografando.
    box = INV_SBOX if is_inv else SBOX
    
    # Percorre as 4 colunas...
    for i in range(len(state)):
        # E as 4 linhas...
        for j in range(len(state[i])):
            # E substitui o valor atual (state[i][j]) pelo mapeamento na caixa.
            state[i][j] = box[state[i][j]]
    return state

def shift_rows(state, is_inv=False):
    """
    Passo 2/4 da Rodada: Deslocamento de Linhas.
    Cruza os dados horizontalmente. Sem isso, cada coluna seria independente e
    o AES seria reduzido a 4 cifras separadas de 32 bits (fácil de quebrar).
    """
    # O loop percorre das linhas 1 a 3 (pois a linha 0, a primeira, NUNCA é movida).
    for r in range(1, 4):
        # A matriz 'state' é indexada por coluna [c][r]. 
        # Aqui extraímos manualmente todos os 4 bytes correspondentes à linha 'r'.
        row = [state[c][r] for c in range(4)]
        
        if not is_inv:
            # Na Encriptação: Movemos os elementos para a ESQUERDA.
            # Linha 1 move 1 casa. Linha 2 move 2 casas. Linha 3 move 3 casas.
            # Em Python, row[r:] pega a partir do índice 'r', e row[:r] pega o começo. Somar os dois faz o "giro".
            shifted = row[r:] + row[:r]
        else:
            # Na Descriptografia: Movemos para a DIREITA para desfazer o passo anterior.
            shifted = row[-r:] + row[:-r]
            
        # Pega a linha que acabou de ser "girada" e injeta de volta na matriz de estado original.
        for c in range(4):
            state[c][r] = shifted[c]
    return state

def mix_columns(state, is_inv=False):
    """
    Passo 3/4 da Rodada: Mistura de Colunas.
    Pega colunas individuais da matriz e aplica a matemática de Galois definida anteriormente.
    """
    # Para cada uma das 4 colunas verticais
    for c in range(4):
        col = state[c]
        # Aplica a multiplicação vetorial correspondente
        if not is_inv:
            state[c] = mix_single_column(col)
        else:
            state[c] = inv_mix_single_column(col)
    return state

def add_round_key(state, round_key):
    """
    Passo 4/4 da Rodada: Adição da Chave.
    Esta é a ÚNICA etapa do processo que utiliza a senha do usuário.
    Garante que tudo feito até agora fique "trancado" atrás do segredo.
    """
    for c in range(4):
        for r in range(4):
            # O símbolo ^ é o XOR (Exclusive OR). 
            # A beleza do XOR é que: (Texto XOR Chave) = Cifra. 
            # E se fizermos (Cifra XOR Chave) = Texto volta a aparecer!
            state[c][r] ^= round_key[c][r]
    return state

# =====================================================================
# 4. EXPANSÃO DE CHAVE (KEY SCHEDULE) - ESPECÍFICO AES-256
# =====================================================================

def expand_key(key):
    """
    Uma rodada AES-256 consome 16 bytes de chave. Mas temos 14 rodadas!
    Além disso, precisamos de mais 1 chave para a transformação inicial.
    Total: 15 chaves de 16 bytes = 240 bytes necessários.
    Mas o usuário só forneceu 32 bytes (256 bits).
    Esta função "expande" os 32 bytes iniciais para as 60 Palavras (Words = 4 bytes)
    necessárias para compor os 240 bytes totais.
    """
    # Nk = Number of words in the Key. 32 bytes / 4 bytes por word = 8 words iniciais.
    Nk = 8 
    # Nr = Number of Rounds. AES-256 usa rigorosamente 14 rodadas.
    Nr = 14
    # Array vazio que abrigará as 60 words da chave expandida.
    words = []

    # 1. As primeiras 8 words são, sem alteração, a própria senha que o usuário digitou.
    for i in range(Nk):
        word = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
        words.append(word)

    # 2. Geração das words 8 a 59 baseada nas anteriores.
    for i in range(Nk, 4 * (Nr + 1)):
        # Guarda a palavra imediatamente anterior (ex: se i=8, pega a word 7).
        temp = words[i - 1][:]
        
        # Rotina Primária de Mistura (executada a cada 8 words - i % 8 == 0):
        if i % Nk == 0:
            # a) RotWord: Pega os 4 bytes e joga o primeiro para o final [b0,b1,b2,b3] -> [b1,b2,b3,b0]
            temp = temp[1:] + temp[:1]
            # b) SubWord: Passa os bytes trocados pela nossa S-Box de confusão.
            temp = [SBOX[b] for b in temp]
            # c) RCON: Faz XOR do primeiro byte do temp com a constante da rodada. Quebra simetrias matemáticas.
            temp[0] ^= RCON[i // Nk]
            
        # REGRA EXCLUSIVA DO AES-256:
        # Pelo fato da chave ser muito grande (32 bytes em vez de 16),
        # a cada metade de ciclo (i % 8 == 4), aplica-se uma camada extra da S-Box
        # para garantir alta não-linearidade sem a necessidade de outro ciclo RotWord.
        elif i % Nk == 4:
            temp = [SBOX[b] for b in temp]

        # Gera a nova word: XOR entre a word calculada há 8 iterações atrás (i - Nk) e nosso 'temp' manipulado.
        word_m_nk = words[i - Nk]
        new_word = [word_m_nk[j] ^ temp[j] for j in range(4)]
        
        # Adiciona a nova palavra à lista.
        words.append(new_word)

    # 3. Formatação Final.
    # Nós temos uma lista longa de 60 words. Mas o núcleo do AES gosta de processar 
    # blocos organizados em grades 4x4 (Round Keys).
    round_keys = []
    for i in range(Nr + 1): # 0 a 14 = 15 Round Keys.
        # Junta 4 words sequenciais e anexa como uma matriz para formar 1 chave de rodada.
        rk = [words[4*i], words[4*i+1], words[4*i+2], words[4*i+3]]
        round_keys.append(rk)
        
    return round_keys

# =====================================================================
# 5. GERENCIAMENTO DE ESTADO E FLUXO PRINCIPAL (ENCRYPT/DECRYPT)
# =====================================================================

def bytes_to_state(data):
    """
    Lê os 16 bytes que vieram do arquivo em disco (sequenciais) e os organiza
    na Matriz de Estado 4x4 necessária para a matemática funcionar.
    Nota crucial: O AES preenche as matrizes por COLUNA, e não por linha.
    """
    state = [[0]*4 for _ in range(4)] # Cria matriz vazia 4x4
    for r in range(4):
        for c in range(4):
            # c avança as colunas, r avança as linhas dentro dessa coluna.
            state[c][r] = data[r + 4*c]
    return state

def state_to_bytes(state):
    """
    Reverte a Matriz de Estado 4x4 (onde ocorreram os cálculos) de volta 
    para um array linear de 16 bytes para que possa ser salvo no HD do computador.
    """
    res = bytearray(16)
    for r in range(4):
        for c in range(4):
            res[r + 4*c] = state[c][r]
    return bytes(res)

def encrypt_block(block, expanded_keys):
    """
    A função mestre que orquestra uma operação AES completa sobre 16 bytes (1 bloco).
    """
    # Validação de segurança estrutural.
    if len(block) != 16:
        raise ValueError("O bloco DEVE ter exatamente 16 bytes.")
        
    # Coloca os bytes crus na matriz 4x4
    state = bytes_to_state(block)
    
    # PASSO A (Initial Transformation): 
    # Apenas um AddRoundKey usando a chave original não modificada (expanded_keys[0]).
    state = add_round_key(state, expanded_keys[0])
    
    # PASSO B (Main Rounds):
    # AES-256 usa 14 rodadas. As rodadas de 1 a 13 são "completas".
    for round_num in range(1, 14):
        state = sub_bytes(state)      # 1. Substitui
        state = shift_rows(state)     # 2. Desloca horizontalmente
        state = mix_columns(state)    # 3. Mistura verticalmente
        state = add_round_key(state, expanded_keys[round_num]) # 4. Tranca com a chave parcial
        
    # PASSO C (Final Round):
    # A última rodada (14) NUNCA possui o MixColumns. Omitir essa etapa na última
    # rodada permite que a estrutura da desencriptação seja perfeitamente simétrica em hardware.
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_keys[14])
    
    # Retorna o tijolo de 16 bytes totalmente ilegível.
    return state_to_bytes(state)

def decrypt_block(block, expanded_keys):
    """
    Reverte o que encrypt_block fez. Para destrancar com êxito,
    todas as operações devem ser feitas em estrita ORDEM REVERSA.
    """
    if len(block) != 16:
        raise ValueError("O bloco cifrado DEVE ter exatamente 16 bytes.")
        
    state = bytes_to_state(block)
    
    # PASSO C Reverso (Reverte o Final Round)
    # A última chave usada foi a de índice 14. Então começamos por ela.
    state = add_round_key(state, expanded_keys[14])
    state = shift_rows(state, is_inv=True) # Move para a direita em vez da esquerda
    state = sub_bytes(state, is_inv=True)  # Usa a tabela INV_SBOX
    
    # PASSO B Reverso (Reverte os Main Rounds)
    # Contagem regressiva da rodada 13 até a 1.
    for round_num in range(13, 0, -1):
        # A ordem das chamadas inverte. A chave que fechava o ciclo agora abre.
        state = add_round_key(state, expanded_keys[round_num])
        state = mix_columns(state, is_inv=True) # Usa constantes Galois 0x0E, 0x0B, etc.
        state = shift_rows(state, is_inv=True)
        state = sub_bytes(state, is_inv=True)
        
    # PASSO A Reverso (Reverte a Initial Transformation)
    # O último toque é aplicar a primeiríssima chave (índice 0).
    state = add_round_key(state, expanded_keys[0])
    
    # O que resta na variável state é o texto original desvendado.
    return state_to_bytes(state)