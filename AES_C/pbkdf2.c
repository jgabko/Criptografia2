#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ====================================================================
 * 1. DEPENDÊNCIAS DO SHA-256
 * O PBKDF2 precisa saber que as funções do SHA-256 existem.
 * Como vamos compilar tudo junto (ou usar #include "sha256.c" no main),
 * declaramos aqui apenas a estrutura e os "protótipos" (assinaturas).
 * ==================================================================== */

// Evita redefinição caso este arquivo seja incluído junto com sha256.c
#ifndef SHA256_CTX_DEFINED
#define SHA256_CTX_DEFINED
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;
#endif

// Assinaturas das funções que implementamos no sha256.c
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);

// Constantes fundamentais do SHA-256
#define SHA256_BLOCK_SIZE 64  // O SHA-256 processa dados em blocos de 64 bytes
#define SHA256_DIGEST_SIZE 32 // O resultado (hash) do SHA-256 tem sempre 32 bytes

/* ====================================================================
 * 2. HMAC-SHA256 (Hash-based Message Authentication Code)
 * O HMAC é uma construção que mistura uma chave (senha) com uma
 * mensagem (salt/dados) usando duas passadas de hash. Isso impede
 * vulnerabilidades matemáticas do hash simples.
 * ==================================================================== */
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out) {
    SHA256_CTX ctx;
    uint8_t k_ipad[SHA256_BLOCK_SIZE]; // Pad Interno (Inner Pad)
    uint8_t k_opad[SHA256_BLOCK_SIZE]; // Pad Externo (Outer Pad)
    uint8_t key_hashed[SHA256_DIGEST_SIZE];

    // PASSO 1: Preparar a chave (Senha)
    // Se a senha for maior que 64 bytes, nós a "encurtamos" fazendo um hash dela.
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_hashed);
        key = key_hashed; // A chave passa a ser o hash da senha original
        key_len = SHA256_DIGEST_SIZE;
    }

    // Inicializa os blocos de pad com zeros
    memset(k_ipad, 0, SHA256_BLOCK_SIZE);
    memset(k_opad, 0, SHA256_BLOCK_SIZE);
    
    // Copia a chave (ou o hash dela) para o início dos pads
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    // PASSO 2: Criar as variações da chave
    // XORamos a chave com duas constantes mágicas (0x36 e 0x5c) para criar
    // duas "subchaves" completamente diferentes a partir da mesma senha.
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // PASSO 3: Hash Interno
    // Calcula: SHA256( k_ipad concatenado com a mensagem )
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE); // Adiciona o ipad
    sha256_update(&ctx, data, data_len);            // Adiciona a mensagem (salt/dados)
    sha256_final(&ctx, inner_hash);                 // Guarda o resultado intermediário

    // PASSO 4: Hash Externo
    // Calcula: SHA256( k_opad concatenado com o inner_hash )
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE); // Adiciona o opad
    sha256_update(&ctx, inner_hash, SHA256_DIGEST_SIZE); // Adiciona o hash calculado no passo 3
    sha256_final(&ctx, out); // Salva o resultado final no ponteiro de saída
}

/* ====================================================================
 * 3. PBKDF2 (Password-Based Key Derivation Function 2)
 * É a função que torna a geração da chave propositalmente lenta (esticamento)
 * para proteger contra ataques de força bruta.
 * ==================================================================== */
void pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t salt_len, 
                   uint32_t iterations, uint32_t dkLen, uint8_t *output) {
    
    uint8_t U[SHA256_DIGEST_SIZE]; // Guarda o resultado temporário do HMAC na iteração atual
    uint8_t T[SHA256_DIGEST_SIZE]; // Bloco acumulador (resultado final de cada bloco)
    uint8_t salt_block[128];       // Buffer de memória para juntar o Salt com o contador de bloco
    
    size_t pass_len = strlen(pass);
    
    // Calcula quantos blocos de 32 bytes precisamos gerar para atingir o tamanho de chave desejado (dkLen).
    // Ex: Se dkLen = 32 (AES-256), precisamos de 1 bloco. Se dkLen = 40, precisamos de 2 blocos.
    uint32_t num_blocks = (dkLen + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;

    // LOOP DOS BLOCOS: Processa cada pedaço da chave final
    for (uint32_t i = 1; i <= num_blocks; i++) {
        
        // PASSO A: Preparar a mensagem inicial (Salt + Índice do Bloco)
        memcpy(salt_block, salt, salt_len);
        
        // O padrão exige que o índice do bloco (i) seja anexado em Big-Endian (4 bytes).
        // Deslocamos os bits (>>) para capturar byte a byte, do mais significativo ao menos.
        salt_block[salt_len + 0] = (i >> 24) & 0xff;
        salt_block[salt_len + 1] = (i >> 16) & 0xff;
        salt_block[salt_len + 2] = (i >> 8)  & 0xff;
        salt_block[salt_len + 3] =  i        & 0xff;

        // PASSO B: Iteração 1 (U1)
        // Calcula o primeiro HMAC usando o Salt concatenado
        hmac_sha256((const uint8_t*)pass, pass_len, salt_block, salt_len + 4, U);
        
        // O primeiro valor de U é copiado para o acumulador T
        memcpy(T, U, SHA256_DIGEST_SIZE);

        // PASSO C: Iterações de Esticamento (U2 até Uc)
        // Isso é o que deixa a função lenta. Executamos milhares de vezes (ex: 100.000).
        for (uint32_t j = 1; j < iterations; j++) {
            
            // O resultado do hash anterior (U) vira a "mensagem" do próximo hash.
            hmac_sha256((const uint8_t*)pass, pass_len, U, SHA256_DIGEST_SIZE, U);
            
            // Acumula matematicamente o resultado fazendo XOR (^) byte a byte com T.
            // O XOR garante que não percamos a "entropia" das iterações anteriores.
            for (int k = 0; k < SHA256_DIGEST_SIZE; k++) {
                T[k] ^= U[k];
            }
        }

        // PASSO D: Escrever o bloco gerado no buffer de saída da chave final
        // Offset é onde vamos começar a escrever (ex: bloco 1 escreve no byte 0, bloco 2 no byte 32)
        uint32_t offset = (i - 1) * SHA256_DIGEST_SIZE;
        
        // Quantos bytes ainda faltam preencher para atingir dkLen?
        uint32_t remaining = dkLen - offset;
        
        // Se estivermos no último bloco, talvez não precisemos dos 32 bytes inteiros (ex: dkLen = 40).
        // Copiamos apenas o que falta.
        uint32_t copy_len = (remaining < SHA256_DIGEST_SIZE) ? remaining : SHA256_DIGEST_SIZE;
        memcpy(output + offset, T, copy_len);
    }
}