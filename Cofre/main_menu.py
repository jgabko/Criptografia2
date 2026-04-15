# Importa o módulo 'file_handler' (que você criou), contendo as lógicas de leitura/escrita e ponte para o AES.
import file_handler 
# Importa o módulo 'sys' do sistema operacional, usado aqui para forçar o encerramento do programa (sys.exit).
import sys
# Importa o módulo 'os', que permite interagir com o sistema de arquivos do seu SO (como checar se um arquivo existe).
import os 

def exibir_menu():
    """
    Função visual simples. Apenas imprime o menu de opções no terminal para orientar o usuário.
    """
    print("\n" + "="*40) # Imprime uma quebra de linha e uma borda de 40 sinais de igual.
    print(" AES-256 ENCRYPTOR/DECRYPTOR TOOL ") # Título da aplicação.
    print("="*40)
    print("[1] Ler arquivo atual (arquivo.txt)") # Opção para ver os dados (em claro ou cifrados).
    print("[2] Encriptar arquivo") # Opção para acionar a cifragem.
    print("[3] Desencriptar arquivo") # Opção para reverter a cifragem.
    print("[0] Sair do software") # Opção para encerrar o loop.
    print("="*40)

def main():
    """
    Função principal que controla o fluxo do programa (Main Loop).
    """
    
    # 1. VERIFICAÇÃO DE AMBIENTE INICIAL
    # os.path.exists() checa se o arquivo apontado na string (no diretório pai '../') já existe no HD.
    if not os.path.exists("../arquivo.txt"):
        # Se não existir (not), ele abre/cria o arquivo em modo de escrita ("w" - write) com codificação UTF-8.
        with open("../arquivo.txt", "w", encoding='utf-8') as f:
            # Escreve um texto inicial (Plaintext) de exemplo no arquivo para que o usuário tenha o que testar.
            f.write("Este e um arquivo secreto de teste inicializado pelo AES.")
        # Informa ao usuário que o arquivo de base foi gerado.
        print("[!] Arquivo de teste padrao 'arquivo.txt' foi criado no diretorio.")

    # 2. LOOP INFINITO DE INTERAÇÃO
    # O 'while True' mantém o programa rodando até que o usuário escolha a opção [0] para quebrar o ciclo.
    while True:
        exibir_menu() # Chama a função que desenha o menu na tela.
        
        # Pede uma entrada do usuário. O '.strip()' remove espaços em branco acidentais antes e depois do texto.
        escolha = input("Selecione uma opção >> ").strip()

        # 3. ROTEAMENTO DAS OPÇÕES
        if escolha == '1':
            # Se digitou 1, delega a tarefa para a função ler_arquivo_atual() no módulo file_handler.
            file_handler.ler_arquivo_atual()
            
        elif escolha == '2':
            # Se digitou 2, primeiro pede a senha que será usada como base para a chave de criptografia.
            senha = input(">> Digite a senha para trancar o arquivo: ")
            if senha: # Verifica se a senha não é uma string vazia (o usuário não apertou apenas Enter).
                # Se for válida, passa a senha para a função de encriptação no file_handler.
                file_handler.encriptar_arquivo(senha)
            else:
                # Se for vazia, nega a execução por segurança.
                print("ERRO: A senha não pode ser um campo vazio.")
                
        elif escolha == '3':
            # Se digitou 3, o processo é idêntico ao 2, mas aciona a destranca (descriptografia).
            senha = input(">> Digite a senha para destrancar o arquivo: ")
            if senha:
                file_handler.desencriptar_arquivo(senha)
            else:
                print("ERRO: A senha não pode ser um campo vazio.")
                
        elif escolha == '0':
            # Se digitou 0, encerra a execução do script no nível do Sistema Operacional passando o código 0 (sucesso).
            print("\nFinalizando as instâncias criptográficas. Adeus.")
            sys.exit(0)
            
        else:
            # Tratamento de exceção para caso o usuário digite letras ou números fora das opções (1, 2, 3, 0).
            print("\n[!] Entrada inválida. Siga os números do menu.")

# Esta estrutura em Python garante que a função main() só seja executada se este arquivo for 
# rodado diretamente (python main_menu.py), e não se for importado por outro script.
if __name__ == "__main__":
    main()