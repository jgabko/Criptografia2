#include <stdint.h>  // Para uint32_t, uint64_t, uint8_t
#include <string.h>  // Para memcpy, memset
#include <stddef.h>  // Para size_t
#include <stdio.h>   // Para printf (saída do hash)
#include <stdlib.h>


uint32_t ROTR(uint32_t x,int num){
    //uint32_t y = x;
   // uint32_t z = x;
    //y= y>>num;
    //z= z<<(32-num);
   //x = y | z;
    //return x;

    return (x >> num) | (x << (32 - num));

}

uint32_t sigma_min_0(uint32_t x){

    uint32_t sigma_min_0_v=  ROTR(x,7)^ROTR(x,18)^(x>>3);
    return sigma_min_0_v;

}

uint32_t sigma_min_1(uint32_t x){

    uint32_t sigma_min_1_v=  ROTR(x,17)^ROTR(x,19)^(x>>10);
    return sigma_min_1_v;
    
}
//[DUVIDA]Voltar e verificar "uint32_t * W"
void cutting(uint32_t blocoX[16],uint32_t * W){

    for(int i = 0; i < 16; i++) {
        W[i] = blocoX[i];
    }

    for(int i = 16; i < 64; i++) {
        W[i] = sigma_min_1(W[i - 2]) + W[i - 7] + sigma_min_0(W[i - 15]) + W[i - 16];
    }

 }

 uint32_t Ch(uint32_t x ,uint32_t y,uint32_t z){

    //Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)
    return (x&&y)^(~x&&z);
 }
//[DUVIDA]Porue ANDs e XORs representam maioria e Choice
 uint32_t Maj(uint32_t x,uint32_t y , uint32_t z){
    //(x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
    return (x&&y)^(x&&z)^(y&&z);
 }

 uint32_t sigma_masc_0(uint32_t x){
    //RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22)
    uint32_t sigma_masc_0_v = ROTR(x,2)^ROTR(x,13)^ROTR(x,22); 
 }

 uint32_t sigma_masc_1(uint32_t x){
    //Σ_1(x) = (x ROTR 6) ⊕ (x ROTR 11) ⊕ (x ROTR 25)
    uint32_t sigma_masc_0_v = ROTR(x,6)^ROTR(x,11)^ROTR(x,25); 
 }

 //[Duvida] 'char *mnsg' e não 'char msng[]'
 uint32_t mnsg_prep(char *mnsg,uint32_t *bloco){


    //char mnsg[]="12345678901234567890";

    //[DUVIDA]
    size_t len_mnsg_byte=strlen(mnsg);
    uint64_t tamanho_bits = (uint64_t)len_mnsg_byte * 8;


    //[DUVIDA] pq len_byte e não em bits
    memcpy(bloco, mnsg, len_mnsg_byte);

    //Adiciona o bit '1' (que em um byte é 0x80) logo após a mensagem
    //[DUVIDA] o local final da mensagem ocupdo pelo index de len_mnsg_bytes já não está ocupado pela mensagem?
    bloco[len_mnsg_byte] = 0x80;

    

    //Preenche com zeros (0x00) até chegar ao byte 56 (que é o bit 448)

    size_t inicio_zeros = len_mnsg_byte + 1;
    size_t quantidade_zeros = 56 - inicio_zeros;

    //[DUVIDA] qual é o conceito e a syntaxe de mmset -> memset(&bloco[inicio_zeros], 0x00, quantidade_zeros);
    // bloco + inicio_zeros
    memset(&bloco[inicio_zeros], 0x00, quantidade_zeros);
   

    //[DUVIDA] Como funciona essa mudança para Big-Endian
    //Adiciona o tamanho original em bits no final (Big-Endian)
    // O SHA-256 exige que o byte mais significativo venha primeiro
    for (int i = 0; i < 8; i++) {
        // Desloca os bits e pega o último byte
        bloco[56 + i] = (tamanho_bits >> (56 - (i * 8))) & 0xFF;
    }

    return bloco;
 }

 void SHA256(char *mnsg_inicial){

   size_t len_mnsg_byte=strlen(mnsg_inicial);
   uint64_t tamanho_bits = (uint64_t)len_mnsg_byte * 8;

   

 }

 void main(){


    
 }