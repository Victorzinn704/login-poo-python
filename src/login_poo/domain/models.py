import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod
from login_poo.domain.errors import (
    ErroAplicacao,
    LoginInvalido,
    SenhaInvalida,
    ConfirmacaoSenhaInvalida,
    PerfilInvalido,
    LoginJaCadastrado,
    UsuarioNaoEncontrado,
    SenhaIncorreta,
    SessaoNaoAutenticada,
    SessaoJaAutenticada,
    PermissaoNegada,
    ConteudoInvalido,
)

class Permissao:
    """Constantes para evitar textos de permissão espalhados pelo código."""

    LEITURA = "leitura"
    ESCRITA = "escrita"


class Perfil:
    LEITOR = "Leitor"
    ESCRITOR = "Escritor"
    LEITOR_ESCRITOR = "Leitor e escritor"
    TODOS = (LEITOR, ESCRITOR, LEITOR_ESCRITOR)


class ValidadorEntrada:
    """Regras puras: não leem o teclado, não imprimem e não alteram o repositório."""

    SENHA_MINIMA = 12
    SENHA_MAXIMA = 128
    LETRAS = "abcdefghijklmnopqrstuvwxyz"
    CARACTERES_LOGIN = LETRAS + "0123456789_."

    @classmethod
    def normalizar_login(cls, login: str) -> str:
        if not isinstance(login, str):
            raise LoginInvalido("O login deve ser um texto.")
        normalizado = login.strip().lower()
        if (
            not 3 <= len(normalizado) <= 30
            or normalizado[0] not in cls.LETRAS
            or any(letra not in cls.CARACTERES_LOGIN for letra in normalizado)
        ):
            raise LoginInvalido(
                "Login inválido: use de 3 a 30 caracteres, começando por uma "
                "letra de a a z; os demais podem ser letras, números, ponto ou _."
            )
        return normalizado

    @classmethod
    def validar_senha_informada(cls, senha: str) -> None:
        # No login, uma senha curta também deve ser comparada à credencial.
        # A exigência de tamanho mínimo pertence à criação da conta.
        if not isinstance(senha, str) or not senha.strip():
            raise SenhaInvalida("Informe uma senha; ela não pode ficar vazia.")
        if len(senha) > cls.SENHA_MAXIMA:
            raise SenhaInvalida(f"A senha deve ter até {cls.SENHA_MAXIMA} caracteres.")

    @classmethod
    def validar_senha_cadastro(cls, senha: str) -> None:
        cls.validar_senha_informada(senha)
        if len(senha) < cls.SENHA_MINIMA:
            raise SenhaInvalida(
                f"A senha deve ter pelo menos {cls.SENHA_MINIMA} caracteres."
            )


class Credencial:
    """Armazena salt e hash derivado; não mantém a senha em texto puro."""

    ITERACOES = 600_000

    def __init__(self, senha: str) -> None:
        ValidadorEntrada.validar_senha_cadastro(senha)
        self.__salt = secrets.token_bytes(16)
        self.__hash = self.__derivar(senha)

    def __derivar(self, senha: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), self.__salt, self.ITERACOES
        )

    def confere(self, senha: str) -> bool:
        ValidadorEntrada.validar_senha_informada(senha)
        return hmac.compare_digest(self.__hash, self.__derivar(senha))


class Usuario(ABC):
    """Base abstrata: identidade e credencial, sem conhecer o console."""

    def __init__(self, login: str, senha: str) -> None:
        self.__login = ValidadorEntrada.normalizar_login(login)
        # COMPOSIÇÃO: a credencial nasce dentro do usuário e pertence a ele.
        self.__credencial = Credencial(senha)

    @property
    def login(self) -> str:
        return self.__login

    @property
    @abstractmethod
    def perfil(self) -> str:
        """Cada subclasse informa o próprio perfil."""
        raise NotImplementedError("A subclasse precisa definir seu perfil.")

    @property
    @abstractmethod
    def permissoes(self) -> frozenset[str]:
        """Conjunto imutável de operações autorizadas para a subclasse."""
        raise NotImplementedError("A subclasse precisa definir suas permissões.")

    def conferir_senha(self, senha: str) -> bool:
        return self.__credencial.confere(senha)

    def pode(self, permissao: str) -> bool:
        return permissao in self.permissoes


class UsuarioLeitor(Usuario):
    @property
    def perfil(self) -> str:
        return Perfil.LEITOR

    @property
    def permissoes(self) -> frozenset[str]:
        return frozenset({Permissao.LEITURA})


class UsuarioEscritor(Usuario):
    @property
    def perfil(self) -> str:
        return Perfil.ESCRITOR

    @property
    def permissoes(self) -> frozenset[str]:
        return frozenset({Permissao.ESCRITA})


class UsuarioLeitorEscritor(Usuario):
    @property
    def perfil(self) -> str:
        return Perfil.LEITOR_ESCRITOR

    @property
    def permissoes(self) -> frozenset[str]:
        return frozenset({Permissao.LEITURA, Permissao.ESCRITA})


def criar_usuario(login: str, senha: str, perfil: str) -> Usuario:
    """Fábrica simples: centraliza a escolha da classe concreta do usuário."""
    classes: dict[str, type[Usuario]] = {
        Perfil.LEITOR: UsuarioLeitor,
        Perfil.ESCRITOR: UsuarioEscritor,
        Perfil.LEITOR_ESCRITOR: UsuarioLeitorEscritor,
    }
    if not isinstance(perfil, str) or perfil not in classes:
        raise PerfilInvalido("Selecione um perfil válido: leitor, escritor ou ambos.")
    return classes[perfil](login, senha)


class Documento:
    LIMITE_CARACTERES = 5_000

    def __init__(self) -> None:
        self.__conteudo = "Este é o documento compartilhado do exercício."

    def ler(self) -> str:
        return self.__conteudo

    def escrever(self, conteudo: str) -> None:
        if not isinstance(conteudo, str) or not conteudo.strip():
            raise ConteudoInvalido("O conteúdo do documento não pode ficar vazio.")
        if len(conteudo) > self.LIMITE_CARACTERES:
            raise ConteudoInvalido(
                f"O documento aceita até {self.LIMITE_CARACTERES} caracteres."
            )
        self.__conteudo = conteudo
