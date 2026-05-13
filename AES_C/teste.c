#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * PBKDF2 - Funcionamento
 *
 * O PBKDF2 recebe:
 *   - Senha (P) → texto original do usuário
 *   - Salt (S) → valor aleatório (evita ataques com tabelas pré-computadas)
 *   - Iterações (c) → número de repetições (ex: 100.000+)
 *   - Função hash (H) → geralmente SHA-256
 *   - Tamanho da chave desejada (dkLen) → ex: 256 bits
 *
 * A derivação da chave ocorre em blocos:
 *   DK = T1 || T2 || ... || Tn
 *
 * Cada bloco Ti é calculado assim:
 *   Ti = U1 ⊕ U2 ⊕ ... ⊕ Uc
 *
 * Onde:
 *   U1 = H(P, S || i)
 *   U2 = H(P, U1)
 *   U3 = H(P, U2)
 *   ...
 *   Uc = H(P, Uc-1)
 *
 * Ou seja: a saída anterior vira entrada da próxima iteração.
 *
 * ------------------------------------------------------------
 * Intuição prática
 *
 * - O PBKDF2 faz:
 *     1. Mistura senha + salt
 *     2. Aplica hash
 *     3. Repete isso milhares de vezes
 *     4. Combina os resultados com XOR
 * - Resultado: uma chave muito difícil de adivinhar, mesmo que a senha seja simples.
 *
 * ------------------------------------------------------------
 * Por que múltiplas iterações?
 *
 * - Sem iterações: atacante testa milhões de senhas por segundo.
 * - Com PBKDF2 (ex: 100k iterações): cada tentativa fica 100.000x mais lenta.
 *
 * ------------------------------------------------------------
 * Papel do SALT
 *
 * - O salt garante que:
 *     • Senhas iguais → chaves diferentes
 *     • Impede rainbow tables
 * - Deve ser:
 *     • Aleatório
 *     • Único por usuário
 *     • Armazenado junto com o hash
 */
    int const c=1000;
    
void pbkdf2(){
    char password[10]= 'senha1234';
    //dklean 32 ou 256 bits
    int dklenbits=32;
    int dklen=dklenbits/32;
    int hashlen=32;
    int Tlen=(dklen/hashlen);
    uint32_t T[Tlen];
    uint32_t dk[dklen];// 
    Tn_function(password,1,c);

}    

void Tn_function(uint8_t password,int i , int c){
    uint32_t salt = saltgenerator(); // não sei como declarar
    uint32_t U[c];
    // 1 pq só queremos 32 bytes
    //============PARTE U =========================
    for(int k=0;k<c;k++){
        if(k=0){
            U[k]=SHA256(password,salt+i);
        }else{
            U[k]=SHA256(password,U[k-1]);

        }
    }
    //============PARTE U =========================

    //============PARTE T ==========================

    uint32_t Temp;
    
    for(int k=0;k<=c;k++){
      
        Temp = Temp ^ U[k];
        
    }
    
    
    memcpy(T[1],Temp,32);





    //============PARTE T ==========================

}
uint32_t dk(uint32_t Tf[c],int Tlen,int dklen){
    uint32_t dk[dklen];
    for(int i=0;i<Tlen;i++){

        dk[i]=Tf[i];
        // não sei como declara o dk_final para somar todos os T1...Tn
    }

}

uint32_t saltgenerator(){
    // não sei como impleemtar
}
