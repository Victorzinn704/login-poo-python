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
from login_poo.domain.models import (
    Permissao,
    Perfil,
    ValidadorEntrada,
    Credencial,
    Usuario,
    UsuarioLeitor,
    UsuarioEscritor,
    UsuarioLeitorEscritor,
    criar_usuario,
    Documento,
)
from login_poo.application.ports import RepositorioUsuarios

class ServicoLogin:
    """Coordena casos de uso; devolve dados ou lança erros, sem input/print."""

    def __init__(self, repositorio: RepositorioUsuarios) -> None:
        # AGREGAÇÃO / INJEÇÃO: o repositório é recebido, não criado aqui.
        self.__repositorio = repositorio
        # COMPOSIÇÃO: cada serviço possui seu próprio documento e sessão local.
        self.__documento = Documento()
        self.__usuario_atual: Usuario | None = None

    @property
    def usuario_atual(self) -> Usuario | None:
        return self.__usuario_atual

    def cadastrar(
        self, login: str, senha: str, confirmacao: str, perfil: str
    ) -> Usuario:
        normalizado = ValidadorEntrada.normalizar_login(login)
        ValidadorEntrada.validar_senha_cadastro(senha)
        if senha != confirmacao:
            raise ConfirmacaoSenhaInvalida("A confirmação não corresponde à senha.")
        if self.__repositorio.buscar(normalizado) is not None:
            raise LoginJaCadastrado("Este login já está cadastrado. Escolha outro.")
        usuario = criar_usuario(normalizado, senha, perfil)
        self.__repositorio.adicionar(usuario)
        return usuario

    def autenticar(self, login: str, senha: str) -> Usuario:
        if self.__usuario_atual is not None:
            raise SessaoJaAutenticada("Saia da conta atual antes de entrar em outra.")
        normalizado = ValidadorEntrada.normalizar_login(login)
        ValidadorEntrada.validar_senha_informada(senha)
        usuario = self.__repositorio.buscar(normalizado)
        if usuario is None:
            raise UsuarioNaoEncontrado("Login não encontrado. Crie uma conta primeiro.")
        if not usuario.conferir_senha(senha):
            raise SenhaIncorreta("Senha incorreta. Tente novamente.")
        # A sessão só é alterada depois de todas as verificações terem passado.
        self.__usuario_atual = usuario
        return usuario

    def sair(self) -> None:
        self.__usuario_atual = None

    def __exigir_permissao(self, permissao: str) -> None:
        usuario = self.__usuario_atual
        if usuario is None:
            raise SessaoNaoAutenticada("Entre em uma conta antes de continuar.")
        # POLIMORFISMO: sem if isinstance(usuario, UsuarioLeitor), por exemplo.
        if not usuario.pode(permissao):
            raise PermissaoNegada(
                f"Acesso negado: seu perfil não permite {permissao}."
            )

    def ler_documento(self) -> str:
        self.__exigir_permissao(Permissao.LEITURA)
        return self.__documento.ler()

    def escrever_documento(self, conteudo: str) -> None:
        self.__exigir_permissao(Permissao.ESCRITA)
        self.__documento.escrever(conteudo)
