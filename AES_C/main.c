#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

// ====================================================================
// Dependências locais
// ====================================================================
#include "SHA256.c" 
#include "pbkdf2.c"
#include "AES.c"

#define ARQUIVO_ALVO "arquivo.txt"
#define ARQUIVO_TEMP "temp.bin"

// ====================================================================
// Função auxiliar para verificar se o arquivo já está encriptado
// (Substitui a lógica de IsBase64 do C#)
// ====================================================================
int parece_encriptado() {
    FILE *f = fopen(ARQUIVO_ALVO, "rb");
    if (!f) return 0;

    int ch;
    int chars_estranhos = 0;
    int total_chars = 0;

    // Lê os primeiros bytes para ver se é binário ou texto legível
    while ((ch = fgetc(f)) != EOF && total_chars < 100) {
        total_chars++;
        // Se não for um caractere imprimível comum, tab ou quebra de linha
        if (!isprint(ch) && ch != '\n' && ch != '\r' && ch != '\t') {
            chars_estranhos++;
        }
    }
    fclose(f);
    
    // Se tiver caracteres não imprimíveis, assumimos que é o binário do AES
    return (chars_estranhos > 0);
}

// ====================================================================
// 1. Ler Arquivo (Equivalente ao ReadFile)
// ====================================================================
void ler_arquivo() {
    FILE *f = fopen(ARQUIVO_ALVO, "rb");
    if (!f) {
        printf("\n✘ arquivo não encontrado.\n");
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    if (size == 0) {
        printf("\n⚠ o arquivo está vazio.\n");
        fclose(f);
        return;
    }

    int encriptado = parece_encriptado();

    printf("\n");
    if (encriptado)
        printf("--- conteúdo cifrado (binario puro) ---\n");
    else
        printf("--- conteúdo legível (plaintext) ---\n");

    int ch;
    while ((ch = fgetc(f)) != EOF) {
        putchar(ch);
    }
    printf("\n-------------------------------------\n");
    fclose(f);
}

// ====================================================================
// 2. Encriptar Arquivo (Equivalente ao EncryptFile)
// ====================================================================
void encriptar_arquivo(const char *senha) {
    if (!fopen(ARQUIVO_ALVO, "rb")) {
        printf("\n✘ arquivo não encontrado.\n");
        return;
    }

    if (parece_encriptado()) {
        printf("\n⚠ arquivo já parece estar encriptado. desencripte primeiro.\n");
        return;
    }

    FILE *fin = fopen(ARQUIVO_ALVO, "rb");
    FILE *fout = fopen(ARQUIVO_TEMP, "wb"); 

    if (!fin || !fout) {
        printf("\n✘ falha ao abrir arquivos para encriptação.\n");
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        return;
    }

    // 1. Gerar Salt
    uint8_t salt[16];
    srand((unsigned int)time(NULL));
    for(int i = 0; i < 16; i++) salt[i] = rand() % 256;
    fwrite(salt, 1, 16, fout);

    // 2. Derivar Chave
    uint8_t chave[32];
    pbkdf2_sha256(senha, salt, 16, 100000, 32, chave);

    // 3. Expandir Chave AES
    uint8_t round_keys[15][16];
    keyexpansion(chave, round_keys);

    // 4. Encriptar
    uint8_t bloco[16];
    size_t bytes_lidos;

    while ((bytes_lidos = fread(bloco, 1, 16, fin)) > 0) {
        if (bytes_lidos < 16) {
            uint8_t pad_value = 16 - bytes_lidos;
            for (size_t i = bytes_lidos; i < 16; i++) bloco[i] = pad_value;
            encrypt_block(bloco, round_keys);
            fwrite(bloco, 1, 16, fout);
            break; 
        } else {
            encrypt_block(bloco, round_keys);
            fwrite(bloco, 1, 16, fout);
            
            int next_char = fgetc(fin);
            if (next_char == EOF) {
                memset(bloco, 16, 16); 
                encrypt_block(bloco, round_keys);
                fwrite(bloco, 1, 16, fout);
                break;
            } else {
                ungetc(next_char, fin);
            }
        }
    }

    fclose(fin);
    fclose(fout);

    remove(ARQUIVO_ALVO);
    rename(ARQUIVO_TEMP, ARQUIVO_ALVO);
    printf("\n✔ arquivo encriptado com sucesso.\n");
}

// ====================================================================
// 3. Decriptar Arquivo (Equivalente ao DecryptFile)
// ====================================================================
void decriptar_arquivo(const char *senha) {
    if (!fopen(ARQUIVO_ALVO, "rb")) {
        printf("\n✘ arquivo não encontrado.\n");
        return;
    }

    if (!parece_encriptado()) {
        printf("\n⚠ conteúdo não parece estar encriptado. encripte primeiro.\n");
        return;
    }

    FILE *fin = fopen(ARQUIVO_ALVO, "rb");
    FILE *fout = fopen(ARQUIVO_TEMP, "wb"); 

    if (!fin || !fout) {
        printf("\n✘ falha ao decriptar: erro ao criar arquivo temporário.\n");
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        return;
    }

    // 1. Ler Salt
    uint8_t salt[16];
    if (fread(salt, 1, 16, fin) != 16) {
        printf("\n✘ conteúdo inválido ou corrompido.\n");
        fclose(fin); fclose(fout);
        remove(ARQUIVO_TEMP);
        return;
    }

    // 2. Derivar Chave
    uint8_t chave[32];
    pbkdf2_sha256(senha, salt, 16, 100000, 32, chave);

    // 3. Expandir Chave AES
    uint8_t round_keys[15][16];
    keyexpansion(chave, round_keys);

    // 4. Decriptar
    uint8_t bloco_atual[16], bloco_anterior[16];
    int primeiro_bloco = 1;
    int erro = 0;

    while (fread(bloco_atual, 1, 16, fin) == 16) {
        if (!primeiro_bloco) {
            fwrite(bloco_anterior, 1, 16, fout);
        }
        dencrypt_block(bloco_atual, round_keys); 
        memcpy(bloco_anterior, bloco_atual, 16);
        primeiro_bloco = 0;
    }

    // Validação do Padding (Simula o CryptographicException do C#)
    if (!primeiro_bloco) {
        uint8_t pad_value = bloco_anterior[15];
        if (pad_value > 0 && pad_value <= 16) {
            int tamanho_real = 16 - pad_value;
            fwrite(bloco_anterior, 1, tamanho_real, fout);
        } else {
            erro = 1;
        }
    } else {
        erro = 1;
    }

    fclose(fin);
    fclose(fout);

    if (erro) {
        printf("\n✘ senha incorreta ou arquivo corrompido. arquivo não foi alterado.\n");
        remove(ARQUIVO_TEMP); 
    } else {
        remove(ARQUIVO_ALVO);
        rename(ARQUIVO_TEMP, ARQUIVO_ALVO);
        printf("\n✔ arquivo decriptado com sucesso.\n");
    }
}

// ====================================================================
// Inicializa o arquivo se ele não existir
// ====================================================================
void inicializar_arquivo() {
    FILE *f = fopen(ARQUIVO_ALVO, "rb");
    if (!f) {
        f = fopen(ARQUIVO_ALVO, "w");
        if (f) {
            fprintf(f, "este é o conteúdo inicial do arquivo.\n");
            fprintf(f, "escreva o que você quer proteger aqui.\n");
            fclose(f);
        }
    } else {
        fclose(f);
    }
}

// ====================================================================
// Leitor de senha helper
// ====================================================================
void ler_senha(const char *prompt, char *senha, int max_len) {
    printf("%s", prompt);
    fgets(senha, max_len, stdin);
    
    size_t len = strlen(senha);
    if (len > 0 && senha[len-1] == '\n') {
        senha[len-1] = '\0';
    }
}

// ====================================================================
// Menu Principal (Idêntico ao C#)
// ====================================================================
int main() {
    inicializar_arquivo();

    int rodando = 1;
    char opcao[10];
    char senha[256];

    while (rodando) {
        // Limpa a tela (funciona no Windows e no Linux/Mac)
        system("cls || clear");

        printf("=== criptografia aes-cbc (trabalho de faculdade) ===\n");
        printf("arquivo: %s\n\n", ARQUIVO_ALVO);
        printf("menu:\n");
        printf("  1 - ler arquivo\n");
        printf("  2 - encriptar arquivo\n");
        printf("  3 - decriptar arquivo\n");
        printf("  0 - sair\n");
        printf("escolha: ");
        
        fgets(opcao, sizeof(opcao), stdin);
        // Remove a quebra de linha da opcao
        opcao[strcspn(opcao, "\n")] = 0;

        if (strcmp(opcao, "1") == 0) {
            printf("\n--- lendo arquivo ---");
            ler_arquivo();
        } 
        else if (strcmp(opcao, "2") == 0) {
            printf("\n");
            ler_senha("digite a senha para encriptar: ", senha, sizeof(senha));
            if (strlen(senha) == 0) {
                printf("\n⚠ senha não pode ser vazia.\n");
            } else {
                encriptar_arquivo(senha);
            }
        } 
        else if (strcmp(opcao, "3") == 0) {
            printf("\n");
            ler_senha("digite a senha para decriptar: ", senha, sizeof(senha));
            if (strlen(senha) == 0) {
                printf("\n⚠ senha não pode ser vazia.\n");
            } else {
                decriptar_arquivo(senha);
            }
        } 
        else if (strcmp(opcao, "0") == 0) {
            rodando = 0;
            printf("\nprograma encerrado. até mais!\n");
        } 
        else {
            printf("\nopção inválida. use 0, 1, 2 ou 3.\n");
        }

        if (rodando) {
            printf("\npressione enter para voltar ao menu...");
            getchar(); // Pausa aguardando o Enter
        }
    }

    return 0;
}