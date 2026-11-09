class ErroAplicacao(Exception):
    """Base dos erros esperados que podem ser apresentados ao usuário."""


class LoginInvalido(ErroAplicacao):
    """O login não respeita o formato aceito."""


class SenhaInvalida(ErroAplicacao):
    """A senha não atende às regras de entrada."""


class ConfirmacaoSenhaInvalida(ErroAplicacao):
    """A confirmação é diferente da senha escolhida."""


class PerfilInvalido(ErroAplicacao):
    """O perfil não corresponde a uma das opções disponíveis."""


class LoginJaCadastrado(ErroAplicacao):
    """O login já pertence a uma conta."""


class UsuarioNaoEncontrado(ErroAplicacao):
    """Não existe uma conta com o login informado."""


class SenhaIncorreta(ErroAplicacao):
    """A senha informada não corresponde à credencial da conta."""


class SessaoNaoAutenticada(ErroAplicacao):
    """A operação exige um usuário autenticado."""


class SessaoJaAutenticada(ErroAplicacao):
    """É preciso sair da conta atual antes de entrar em outra."""


class PermissaoNegada(ErroAplicacao):
    """O usuário está autenticado, mas não pode realizar a operação."""


class ConteudoInvalido(ErroAplicacao):
    """O texto não atende às regras do documento."""
