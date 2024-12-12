# Tentativas-invasao-Logs
Detecção de Tentativas de Invasão em Logs - Desafio de código DIO Bootcamp CyberSecurity2

Você é responsável por implementar um sistema de monitoramento de segurança para um sistema de acesso. Seu objetivo é analisar registros de log de tentativas de acesso para detectar possíveis invasões. Cada registro contém um identificador de usuário e um status que indica se a tentativa de acesso foi bem-sucedida ou falhou.

A detecção de tentativas de invasão é essencial para a segurança do sistema, e a análise de logs é uma prática comum para identificar comportamentos suspeitos. O sistema deve emitir um alerta se detectar mais de 3 tentativas consecutivas de falha para o mesmo usuário.

Entrada
Uma lista de registros de log no formato id_usuario:status, onde:

id_usuario é uma string que representa o identificador do usuário (exemplo: "user1").

status pode ser uma das seguintes strings:
- "sucesso" – indica que a tentativa de acesso foi bem-sucedida.
- "falha" – indica que a tentativa de acesso falhou.

A lista pode conter qualquer número de registros.

Saída
O sistema deve retornar:

O id_usuario que teve mais de 3 tentativas consecutivas de falha.

Se nenhum usuário tiver mais de 3 tentativas de falha consecutivas, o sistema deve retornar a mensagem "Nenhum invasor detectado".

Exemplos
A tabela abaixo apresenta exemplos com alguns dados de entrada e suas respectivas saídas esperadas. Certifique-se de testar seu programa com esses exemplos e com outros casos possíveis.

Entrada	Saída
user1:falha, user1:falha, user1:falha, user1:sucesso = Nenhum invasor detectado
user2:falha, user2:falha, user2:falha, user2:falha = user2
user3:sucesso, user3:falha, user3:falha, user3:falha, user3:falha = user3
.....

def detectar_invasao(registros):
    usuario_atual = None
    tentativas_consecutivas = 0
    invasor_detectado = None

    for registro in registros:
        usuario, status = registro.split(":")

        if usuario_atual == usuario:
            tentativas_consecutivas += 1 if status == "falha" else 0
            if tentativas_consecutivas >= 3:
                invasor_detectado = usuario
                break
        else:
            usuario_atual = usuario
            tentativas_consecutivas = 4 if status == "sucesso" else 0

    return invasor_detectado if invasor_detectado else "Nenhum invasor detectado"

def main():
    entrada = input()
    registros = [registro.strip() for registro in entrada.split(",")]

    resultado = detectar_invasao(registros)
    print(resultado)

if __name__ == "__main__":
    main()
