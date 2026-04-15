import os # Para verificar caminhos e arquivos no disco.
import base64 # Usado para transformar bytes ilegíveis de cifra em texto puro legível/salvável.
import hashlib # Biblioteca que contém algoritmos de Hashing (usaremos o SHA-256).
import aes_core # O núcleo matemático puro do AES que construímos previamente.

# Constante global apontando para o arquivo que será manipulado. O "../" indica um diretório acima de onde o script roda.
FILE_NAME = "../arquivo.txt"

# =====================================================================
# FUNÇÕES AUXILIARES DE CRIPTOGRAFIA
# =====================================================================

def derive_key(password):
    """
    Função de Derivação de Chave (KDF - Key Derivation Function).
    O AES-256 não aceita senhas de tamanhos aleatórios. Ele exige EXATAMENTE 32 bytes (256 bits).
    """
    # 1. password.encode('utf-8'): Converte a string digitada (ex: "senha123") em bytes.
    # 2. hashlib.sha256(...): Aplica a função de hash criptográfico unidirecional SHA-256 aos bytes.
    # 3. .digest(): Retorna o resultado matemático do Hash em formato de bytes brutos.
    # Resultado final: Qualquer senha (de 1 a 1000 caracteres) se transforma sempre em uma chave de 32 bytes.
    return hashlib.sha256(password.encode('utf-8')).digest()

def pad(data):
    """
    PKCS#7 Padding.
    Cifras de Bloco (como o AES) só trabalham em pedaços de tamanho fixo. O AES usa blocos de 16 bytes.
    Se a sua mensagem tem 20 bytes, o primeiro bloco usa 16. O segundo bloco só tem 4.
    Faltam 12 bytes para o AES conseguir processar. Esta função resolve isso.
    """
    # Calcula quantos bytes faltam para o dado se tornar múltiplo de 16.
    # (len(data) % 16) pega o resto. Ex: 20 % 16 = 4. Logo, 16 - 4 = 12 bytes faltantes.
    pad_len = 16 - (len(data) % 16)
    
    # O PKCS#7 dita que o valor do byte de preenchimento deve ser igual ao número de bytes preenchidos.
    # Se faltam 12 bytes, ele adiciona 12 bytes, todos com o valor hexadecimal 0x0C (12).
    # 'data +' concatena os dados originais com o preenchimento.
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """
    Remove o PKCS#7 Padding após o arquivo ser descriptografado para retornar o texto exato.
    """
    # Pega o último byte do arquivo descriptografado, pois o PKCS#7 sempre coloca o tamanho lá.
    pad_len = data[-1]
    
    # Retorna todos os dados até aquele ponto (exclui os últimos X bytes correspondentes ao padding).
    # Ex: se o último byte for 12, ele corta os últimos 12 bytes (data[:-12]).
    return data[:-pad_len]

# =====================================================================
# FUNÇÕES DE AÇÃO PRINCIPAL
# =====================================================================

def ler_arquivo_atual():
    """
    Abre o arquivo alvo apenas para leitura e joga o conteúdo no terminal.
    """
    # Se o arquivo não existir, aborta para não gerar erro no Python (Crash).
    if not os.path.exists(FILE_NAME):
        print(f"\n[!] Arquivo '{FILE_NAME}' não encontrado. Crie um arquivo com algum texto para iniciar.")
        return

    # Abre o arquivo no modo 'r' (read as text), codificação utf-8. 
    # errors='replace' impede que caracteres estranhos travem a leitura (útil se lermos um arquivo encriptado).
    with open(FILE_NAME, 'r', encoding='utf-8', errors='replace') as f:
        conteudo = f.read() # Lê o arquivo inteiro para a memória.
        print(f"\n--- Conteúdo atual de {FILE_NAME} ---")
        print(conteudo)
        print("-" * 40)

def encriptar_arquivo(senha):
    """
    Orquestra a leitura do Plaintext, transformação e gravação do Ciphertext.
    """
    if not os.path.exists(FILE_NAME):
        print(f"\n[!] Arquivo '{FILE_NAME}' não encontrado.")
        return

    # 1. PREPARAÇÃO DA CHAVE E EXPANÇÃO
    # Gera a chave de 32 bytes através da senha fornecida usando a nossa função auxiliar.
    key = derive_key(senha)
    # Chama o núcleo AES (aes_core) para computar as "Round Keys" baseadas na nossa chave mestre de 32 bytes.
    # São calculadas todas as chaves parciais usadas nas 14 rodadas do AES-256.
    expanded_keys = aes_core.expand_key(key)

    # 2. LEITURA DOS DADOS
    # Abre o arquivo no modo 'rb' (read bytes). Aqui não tratamos como string, e sim como dados binários crus.
    with open(FILE_NAME, 'rb') as f:
        plaintext = f.read()

    # 3. PADDING E PREPARAÇÃO
    # Adiciona o preenchimento PKCS#7 para garantir que os dados sejam múltiplos matemáticos de 16.
    padded_data = pad(plaintext)
    # Cria um array de bytes vazio onde vamos acoplar os blocos já encriptados um a um.
    ciphertext = bytearray()

    # 4. LOOP DE ENCRIPTAÇÃO (MODO ECB - Electronic Codebook)
    # O range avança de 16 em 16 bytes sobre os dados preparados.
    for i in range(0, len(padded_data), 16):
        # 'Fatia' o dado: pega do índice i até i+16 (ou seja, exatamente 1 bloco).
        block = padded_data[i:i+16]
        
        # Envia aquele bloco único de 16 bytes e as chaves calculadas para o 'aes_core'.
        # O núcleo devolve o bloco totalmente embaralhado.
        encrypted_block = aes_core.encrypt_block(block, expanded_keys)
        
        # Anexa o bloco encriptado no resultado final (ciphertext).
        ciphertext.extend(encrypted_block)

    # 5. CODIFICAÇÃO BASE64 E SALVAMENTO
    # O AES cospe bytes que muitas vezes não são caracteres de texto válidos (causariam corrupção no TXT).
    # A base64.b64encode mapeia esses bytes aleatórios em caracteres padrão ASCII seguros (letras, números, +, /).
    # .decode('utf-8') transforma o resultado do Base64 em uma string de fato no Python.
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    
    # Sobrescreve o arquivo original abrindo no modo 'w' (write text) e inserindo o texto Base64 cifrado.
    with open(FILE_NAME, 'w', encoding='utf-8') as f:
        f.write(encoded_ciphertext)
        
    print("\n[+] Arquivo encriptado com sucesso (Salvo em formato Base64)!")

def desencriptar_arquivo(senha):
    """
    Processo exato e espelhado de forma reversa ao encriptar_arquivo.
    """
    if not os.path.exists(FILE_NAME):
        print(f"\n[!] Arquivo '{FILE_NAME}' não encontrado.")
        return

    # A chave precisa ser idêntica à usada na encriptação para o processo ser bem sucedido.
    key = derive_key(senha)
    # Expande as chaves novamente para fornecer as Round Keys.
    expanded_keys = aes_core.expand_key(key)

    # Lê a string codificada em Base64 que está no arquivo.
    with open(FILE_NAME, 'r', encoding='utf-8') as f:
        encoded_ciphertext = f.read()

    # Tenta reverter o Base64 legível para os bytes crus criptografados.
    try:
        ciphertext = base64.b64decode(encoded_ciphertext)
    except Exception:
        # Se falhar, é porque o arquivo lido não obedece as regras do Base64 (talvez já seja um texto normal/limpo).
        print("\n[!] O arquivo não parece estar em Base64. Já está desencriptado?")
        return

    # Prepara o recipiente para os bytes resolvidos, com padding ainda incluso.
    decrypted_padded = bytearray()

    try:
        # Pega a matriz de bytes confusa e avança de 16 em 16 bytes.
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            
            # Chama a função de descriptografia do AES_Core (reverte MixColumns, ShiftRows, SubBytes, etc).
            decrypted_block = aes_core.decrypt_block(block, expanded_keys)
            
            # Anexa os bytes reais descobertos de volta na fila.
            decrypted_padded.extend(decrypted_block)

        # Removemos os bytes adicionais (0x0C, por exemplo) que a função 'pad()' inseriu antes de encriptar.
        plaintext = unpad(decrypted_padded)

        # Abre o arquivo em modo de escrita binária ('wb') e salva a informação pura e original de volta ao disco.
        with open(FILE_NAME, 'wb') as f:
            f.write(plaintext)
            
        print("\n[+] Arquivo desencriptado com sucesso! Texto original restaurado.")
    except Exception:
        # Se ocorrer um erro durante a desencriptação ou remoção de padding, o Catch é acionado.
        # Geralmente isso acontece se a senha for incorreta (o AES gera blocos sem sentido e a função unpad() falha ao achar o padding correto).
        print("\n[!] Falha grave na decriptação! Senha errada ou arquivo corrompido.")