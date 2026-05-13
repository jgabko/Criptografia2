import hmac
import hashlib
import os

def xor_bytes(bloco_a: bytes, bloco_b: bytes) -> bytes:
    """
    Função auxiliar para fazer a operação XOR bit a bit entre dois blocos de bytes.
    Equivale ao símbolo ⊕ na sua fórmula.
    """
    # Junta os bytes de mesma posição com zip() e aplica XOR (^) em cada par.
    return bytes(a ^ b for a, b in zip(bloco_a, bloco_b))

def pbkdf2_hmac_sha256_manual(senha: bytes, salt: bytes, iteracoes: int, dkLen: int) -> bytes:
    """
    Implementação manual do PBKDF2 usando HMAC-SHA256 como Função Hash (H).
    
    :param senha: (P) A senha original em bytes.
    :param salt: (S) O valor aleatório em bytes.
    :param iteracoes: (c) Número de vezes que o hash será aplicado.
    :param dkLen: Tamanho da chave derivada desejada em bytes (ex: 32 para AES-256).
    """
    
    # O tamanho do hash de saída do SHA-256 é sempre 32 bytes (256 bits).
    hLen = 32 
    
    # Se a chave desejada for maior que o hash, precisamos de múltiplos blocos (T1, T2... Tn).
    # O cálculo abaixo é o equivalente a arredondar para cima a divisão: dkLen / hLen
    # Para AES-256 (dkLen = 32), precisamos de exatamente 1 bloco (32 / 32 = 1).
    num_blocos = (dkLen + hLen - 1) // hLen
    
    # DK (Derived Key) vai armazenar a chave final concatenada.
    DK = b""
    
    # O algoritmo constrói a chave bloco por bloco (T_1, T_2, ..., T_n)
    # i começa em 1, e não em 0, conforme especificação do PBKDF2.
    for i in range(1, num_blocos + 1):
        
        # Converte o número do bloco 'i' em uma representação de 4 bytes (Inteiro de 32 bits, Big-Endian)
        # Isso equivale à notação 'i' na fórmula U1 = H(P, S || i)
        i_bytes = i.to_bytes(4, byteorder='big')
        
        # =====================================================================
        # PRIMEIRA ITERAÇÃO (U_1)
        # Fórmula: U_1 = H(P, S || i)
        # =====================================================================
        
        # Concatena o Salt (S) com o número do bloco (i) -> (S || i)
        mensagem_u1 = salt + i_bytes
        
        # Aplica o HMAC-SHA256 usando a Senha (P) como chave e (S || i) como mensagem.
        # .digest() retorna os bytes puros do hash.
        u_atual = hmac.new(senha, mensagem_u1, hashlib.sha256).digest()
        
        # Inicializa o Bloco T_i. Na primeira rodada, T_i é igual a U_1.
        # T_i = U_1
        T_i = u_atual
        
        # =====================================================================
        # ITERAÇÕES SEGUINTES (U_2 até U_c)
        # Fórmula: U_c = H(P, U_{c-1}) e T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
        # =====================================================================
        
        # O loop roda da iteração 2 até a iteração total 'c'
        for _ in range(1, iteracoes):
            # U_{atual} = H(P, U_{anterior})
            # A saída da rodada anterior vira a entrada da nova rodada.
            u_atual = hmac.new(senha, u_atual, hashlib.sha256).digest()
            
            # Acumula o resultado usando a operação XOR (⊕) com o estado atual de T_i
            # T_i = T_i ⊕ U_{atual}
            T_i = xor_bytes(T_i, u_atual)
            
        # Após terminar as iterações (c), concatenamos o bloco T_i na chave final DK
        # DK = T_1 || T_2 || ... || T_n
        DK += T_i
        
    # Como podemos ter gerado blocos a mais do que o necessário, 
    # retornamos apenas os 'dkLen' primeiros bytes.
    return DK[:dkLen]

# ============================================================
# EXEMPLO DE USO: GERANDO CHAVE PARA AES-256
# ============================================================

if __name__ == "__main__":
    # 1. Definindo a senha original do usuário (P)
    senha_texto = "minha_senha_super_secreta"
    senha_bytes = senha_texto.encode('utf-8')
    
    # 2. Gerando um Salt (S) aleatório. 
    # Na prática, você salva esse salt junto com o texto cifrado no banco de dados.
    # Recomendado: 16 bytes para boa segurança.
    salt = os.urandom(16) 
    
    # 3. Definindo iterações (c). 
    # O recomendado hoje em dia pelo NIST e OWASP é de pelo menos 210.000 para SHA-256, 
    # mas usaremos 100.000 como no seu exemplo.
    iteracoes = 100000 
    
    # 4. Definindo o tamanho da chave (dkLen)
    # AES-256 precisa de uma chave de 256 bits, que equivalem a 32 bytes (256 / 8).
    tamanho_chave_aes256 = 32 
    
    print("Iniciando derivação (Isso pode levar uma fração de segundo por causa das iterações)...")
    
    # Chamando a nossa implementação "na mão"
    chave_aes = pbkdf2_hmac_sha256_manual(senha_bytes, salt, iteracoes, tamanho_chave_aes256)
    
    print("\n--- RESUMO ---")
    print(f"Senha original: '{senha_texto}'")
    print(f"Salt (Hex)    : {salt.hex()}")
    print(f"Iterações     : {iteracoes}")
    print(f"\nCHAVE AES-256 GERADA (Hex):")
    print(f"{chave_aes.hex()}")
    print(f"Tamanho da chave: {len(chave_aes)} bytes")