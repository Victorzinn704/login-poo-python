from getpass import getpass
from login_poo.application.service import ServicoLogin
from login_poo.infrastructure.memory import RepositorioUsuariosEmMemoria
from login_poo.presentation.console import AplicacaoConsole

def criar_aplicacao(ler=input, mostrar=print, ler_senha=getpass) -> AplicacaoConsole:
    repositorio = RepositorioUsuariosEmMemoria()
    servico = ServicoLogin(repositorio)
    return AplicacaoConsole(servico, ler, mostrar, ler_senha)
