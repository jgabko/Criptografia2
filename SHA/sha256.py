import struct

# =====================================================================
# FERRAMENTAS MATEMÁTICAS (Todas com Soma Modular de 32 bits)
# O "& 0xFFFFFFFF" garante que nenhum valor passe de 32 bits, 
# simulando o limite físico dos registradores ("Soma Modular").
# =====================================================================

def rotr(x, n):
    """Rotação Circular para a Direita (ROTR). Os bits dão a volta."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    """Função de Escolha (Choice): x decide se o bit sai de y ou de z."""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Função de Maioria (Majority): Vence o bit (0 ou 1) que aparecer mais."""
    return (x & y) ^ (x & z) ^ (y & z)

# Minúsculos: Bagunçam as palavras da MENSAGEM (Usam Shift >> para perder bits)
def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

# Maiúsculos: Bagunçam as variáveis A e E (Não perdem bits, só Rotação)
def Sigma0(a):
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)

def Sigma1(e):
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)


# =====================================================================
# CONSTANTES (O "Tempero" do Algoritmo)
# =====================================================================

# K: As 64 constantes derivadas das raízes cúbicas dos primeiros 64 números primos.
# Elas garantem que cada uma das 64 rodadas seja matematicamente única.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


# =====================================================================
# O CORAÇÃO DO ALGORITMO SHA-256
# =====================================================================

def meu_sha256(mensagem_texto):
    
    # Converte o texto para bytes (zeros e uns)
    mensagem_bytes = mensagem_texto.encode('utf-8')
    tamanho_original_bits = len(mensagem_bytes) * 8 #quantidade de bytes * 8

    # ---------------------------------------------------------
    # PASSO 1: Preparação da Mensagem (Padding)
    # ---------------------------------------------------------
    # Adiciona o bit '1' (em hexadecimal, 0x80 é 10000000)
    mensagem_bytes += b'\x80'  #*Não entendi muito bem
    
    # Adiciona os bits '0' até chegar no alvo: 448 bits (módulo 512).
    # Em bytes, 448 bits = 56 bytes. 512 bits = 64 bytes.
    while (len(mensagem_bytes) % 64) != 56:
        mensagem_bytes += b'\x00'
        
    # Adiciona os 64 bits exatos com o tamanho original da mensagem
    # O comando struct.pack('>Q') faz exatamente essa conversão para binário de 64 bits.
    mensagem_bytes += struct.pack('>Q', tamanho_original_bits)
    
    # ---------------------------------------------------------
    # PASSO 2: Inicialização dos Registradores (Raízes dos 8 primos)
    # ---------------------------------------------------------
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # =========================================================
    # INÍCIO DO LAÇO DE REPETIÇÃO DOS BLOCOS (Merkle-Damgård)
    # Aqui o algoritmo pega de 512 em 512 bits (64 bytes)
    # =========================================================
    for i in range(0, len(mensagem_bytes), 64):
        bloco = mensagem_bytes[i : i+64]
        
        # ---------------------------------------------------------
        # PASSO 3: Expansão da Mensagem (Criando W[0] a W[63])
        # ---------------------------------------------------------
        # Fatiamos os 512 bits em 16 pedaços de 32 bits puros (W[0] a W[15])
        W = list(struct.unpack('>16I', bloco))
        
        # Expandimos os próximos 48 pedaços usando a equação de difusão
        for t in range(16, 64):
            nova_palavra = (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16])
            # Aplicamos & 0xFFFFFFFF para fazer a soma modular
            W.append(nova_palavra & 0xFFFFFFFF)
            
        # ---------------------------------------------------------
        # FASE 4.1: O Passo Oculto (Preparação do Liquidificador)
        # ---------------------------------------------------------
        # As variáveis a-h recebem os valores que o bloco anterior deixou salvo.
        # Se for o Bloco 1, elas recebem os valores originais do Passo 2.
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]
        
        # ---------------------------------------------------------
        # FASE 4.2: O Processo de Compressão (As 64 rodadas)
        # ---------------------------------------------------------
        for t in range(64):
            # Calcula o Impacto Inferior (A mensagem W e a chave K entram aqui)
            T1 = (h + Sigma1(e) + ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
            
            # Calcula o Impacto Superior (Só bagunça o que já estava lá)
            T2 = (Sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            
            # A Queda em Cascata: Todo mundo escorrega um degrau
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF # O Impacto T1 entra no meio da fila
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF # O Topo recebe a carga máxima
            
        # ---------------------------------------------------------
        # PASSO 5: O Encadeamento / O Salve (Merkle-Damgård)
        # ---------------------------------------------------------
        # O bloco terminou. Somamos o resultado maluco do liquidificador
        # aos registradores H. Isso salva o legado deste bloco para
        # que o próximo bloco inicie o Passo 4.1 com esses novos valores.
        H[0] = (H[0] + a) & 0xFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFF
        H[5] = (H[5] + f) & 0xFFFFFFFF
        H[6] = (H[6] + g) & 0xFFFFFFFF
        H[7] = (H[7] + h) & 0xFFFFFFFF
        
    # FIM DO LAÇO DOS BLOCOS
        
    # ---------------------------------------------------------
    # PASSO 6: Geração do Hash Final
    # ---------------------------------------------------------
    # Junta (concatena) os 8 blocos de 32 bits formatando-os em Hexadecimal
    # (Cada bloco de 32 bits vira 8 letras/números hexadecimais).
    hash_final = "".join(f"{valor:08x}" for valor in H)
    
    return hash_final


# =====================================================================
# ÁREA DE TESTE
# =====================================================================
if __name__ == "__main__":
    import hashlib # Apenas para validar se o nosso funciona!

    # Pode testar com o tamanho de texto que quiser
    texto = "Entendi perfeitamente como o SHA-256 funciona!"
    
    meu_resultado = meu_sha256(texto)
    resultado_oficial = hashlib.sha256(texto.encode('utf-8')).hexdigest()
    
    print("=== TESTE DO SHA-256 FEITO DO ZERO ===")
    print(f"Mensagem   : '{texto}'")
    print(f"Nosso Hash : {meu_resultado}")
    print(f"Python Hash: {resultado_oficial}")
    print("--------------------------------------")
    if meu_resultado == resultado_oficial:
        print("SUCESSO")
    else:
        print("Ops, algo deu errado.")