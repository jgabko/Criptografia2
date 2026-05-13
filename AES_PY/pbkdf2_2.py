import hmac
import hashlib
import os

# ============================================================
# MÉTODOS AUXILIARES (As máquinas que você mapeou)
# ============================================================

def create_salt():
    """Faz o salt (Gera 16 bytes aleatórios)"""
    return os.urandom(16)

def concat(salt, i):
    """Faz o concat simples de salt com i"""
    # i.to_bytes(4, 'big') transforma o número (ex: 1) em 4 bytes para o SHA entender
    return salt + i.to_bytes(4, byteorder='big')

def SHA(password, mensagem):
    """Implementa o hash sha256 (usando HMAC conforme a RFC)"""
    return hmac.new(password, mensagem, hashlib.sha256).digest()

def xor_sum(lista_uc):
    """Faz o xor de todos os elementos de uma array"""
    # Pega o primeiro elemento (U_1) para ser a base
    resultado = lista_uc[0]
    
    # Faz um loop pelos elementos restantes (U_2 até U_c) e aplica o XOR
    for u in lista_uc[1:]:
        # Faz o XOR byte a byte usando zip, igual vimos antes
        resultado = bytes(a ^ b for a, b in zip(resultado, u))
        
    return resultado

def concat_list(Ttotal):
    """Faz o concat do array inteiro (T_1 || T_2...)"""
    return b"".join(Ttotal)

# ============================================================
# LÓGICA PRINCIPAL (A sua arquitetura)
# ============================================================

def uc(c, i, salt, password):
    """Gera uma lista com todas as iterações U_1 até U_c"""
    lista_uc = []
    
    # O primeiro U (U_1) concatena o salt com o i
    mensagem_inicial = concat(salt, i)
    u_atual = SHA(password, mensagem_inicial)
    lista_uc.append(u_atual)
    
    # As repetições seguintes usam apenas o U anterior
    # range(1, c) vai rodar c-1 vezes, completando o total de c
    for j in range(1, c):
        u_atual = SHA(password, u_atual)
        lista_uc.append(u_atual)
        
    # Retorna o array contendo [U_1, U_2, U_3 ... U_c]
    return lista_uc
    
def ti(c, i, salt, password):
    """Orquestra a criação do array UC e depois faz o XOR sum dele"""
    # 1. Chama a função uc para gerar o array completo
    array_de_us = uc(c, i, salt, password)
    
    # 2. Passa o array para o xor_sum e retorna o bloco final T_i
    return xor_sum(array_de_us)

def dk():
    """Função principal que monta a chave"""
    c = 100000 # Número de repetições
    salt = create_salt()
    # A senha precisa ser convertida para bytes em Python (adicionando o b"")
    password = b"senhalegal1234" 
    
    chave_len = 256 # em bits
    T_bytes = chave_len // 8 # Convertendo 256 bits para 32 bytes
    
    # O SHA256 retorna 32 bytes. Precisamos descobrir quantos blocos gerar.
    Tlen = (T_bytes + 32 - 1) // 32 
    
    Ttotal = []
    
    # A fórmula do PBKDF2 dita que o índice dos blocos começa em 1, não em 0.
    for i in range(1, Tlen + 1):
        # Calcula o bloco T_i atual e adiciona na lista
        bloco_atual = ti(c, i, salt, password)
        Ttotal.append(bloco_atual)

    # Concatena a lista de blocos
    chave = concat_list(Ttotal)

    # Retorna cortando no tamanho exato solicitado
    return chave[:T_bytes]

# ============================================================
# EXECUÇÃO DO CÓDIGO
# ============================================================
if __name__ == "__main__":
    print("Gerando chave pela sua arquitetura original...")
    minha_chave = dk()
    print(f"\nCHAVE GERADA (HEX): {minha_chave.hex()}")