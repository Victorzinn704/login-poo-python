import argparse
from getpass import getpass
from login_poo.bootstrap import criar_aplicacao
from login_poo.presentation.console import FEEDBACK_IA

def main(argumentos=None, ler=input, mostrar=print, ler_senha=getpass) -> int:
    from login_poo.selftest import executar_testes
    parser = argparse.ArgumentParser(description="Login POO com biblioteca padrão.")
    modos = parser.add_mutually_exclusive_group()
    modos.add_argument("--testes", action="store_true", help="Executa a suíte unittest.")
    modos.add_argument("--feedback", action="store_true", help="Mostra o relato sobre a IA.")
    opcoes = parser.parse_args(argumentos)
    if opcoes.testes:
        return 0 if executar_testes(mostrar) else 1
    if opcoes.feedback:
        mostrar(FEEDBACK_IA)
        return 0
    try:
        criar_aplicacao(ler, mostrar, ler_senha).executar()
    except (EOFError, KeyboardInterrupt):
        mostrar("\nEntrada interrompida. Programa encerrado.")
    return 0
