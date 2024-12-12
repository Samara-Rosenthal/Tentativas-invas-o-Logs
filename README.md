# Tentativas-invasao-Logs
Detecção de Tentativas de Invasão em Logs

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
