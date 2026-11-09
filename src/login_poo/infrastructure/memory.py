from login_poo.application.ports import RepositorioUsuarios
from login_poo.domain.models import Usuario
from login_poo.domain.errors import LoginJaCadastrado

class RepositorioUsuariosEmMemoria(RepositorioUsuarios):
    def __init__(self) -> None:
        self.__usuarios: dict[str, Usuario] = {}

    def adicionar(self, usuario: Usuario) -> None:
        if usuario.login in self.__usuarios:
            raise LoginJaCadastrado("Este login já está cadastrado. Escolha outro.")
        self.__usuarios[usuario.login] = usuario

    def buscar(self, login: str) -> Usuario | None:
        return self.__usuarios.get(login)
