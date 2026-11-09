from abc import ABC, abstractmethod
from login_poo.domain.models import Usuario

class RepositorioUsuarios(ABC):
    """Contrato de armazenamento: o serviço não precisa conhecer um banco."""

    @abstractmethod
    def adicionar(self, usuario: Usuario) -> None:
        """Armazena sem sobrescrever; levanta LoginJaCadastrado se já existir."""
        raise NotImplementedError("Implemente a operação adicionar do repositório.")

    @abstractmethod
    def buscar(self, login: str) -> Usuario | None:
        """Busca por login normalizado; retorna None quando não encontra."""
        raise NotImplementedError("Implemente a operação buscar do repositório.")
