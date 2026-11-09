#!/usr/bin/env python3
"""Sistema de login didático em um único arquivo, COM IMPORTAÇÕES — Python 3.10+.

COMO EXECUTAR (a partir da pasta do projeto)
    python3 exercicios/login_poo_com_import.py
    python3 exercicios/login_poo_com_import.py --testes
    python3 exercicios/login_poo_com_import.py --feedback
    No menu inicial: 3 executa os testes e 4 apresenta o feedback sobre a IA.
    Todos os módulos usados pertencem à biblioteca padrão: não é necessário pip.

ROTEIRO PARA APRESENTAR O TRABALHO
    1. Cadastre três contas, escolhendo um perfil diferente para cada uma.
    2. Entre como leitor: a leitura funciona e a escrita é negada.
    3. Saia da conta e entre como escritor: a escrita funciona e a leitura é negada.
    4. Entre como leitor/escritor: as duas operações funcionam.
    5. Experimente login inexistente, senha incorreta e cadastro duplicado.
    6. Saia da conta e escolha 3 para os testes ou 4 para o feedback.

MAPA DOS CONCEITOS OBRIGATÓRIOS
    Herança: UsuarioLeitor, UsuarioEscritor e UsuarioLeitorEscritor herdam Usuario.
    Interface: RepositorioUsuarios define um contrato com ABC e abstractmethod.
        Python impede instanciar a interface ou uma implementação incompleta.
        Usuario também usa ABC para exigir perfil e permissões nas subclasses.
    Agregação: ServicoLogin recebe um repositório criado fora dele. O mesmo
        repositório pode atender a outros serviços e existir sem este serviço.
    Composição: Usuario cria e possui sua Credencial; ServicoLogin cria e possui
        seu Documento. Esses objetos internos não são injetados nem compartilhados.
    Polimorfismo: o serviço consulta usuario.permissoes sem testar a subclasse.
    Encapsulamento: credencial, sessão e conteúdo são detalhes internos.
    Baixo acoplamento: o serviço depende do contrato do repositório; o console
        depende do serviço. Estarem no mesmo arquivo não mistura responsabilidades.

FLUXO E CONTRATOS
    Console -> ServicoLogin -> RepositorioUsuarios / Usuario / Documento
    Entrada inválida -> raise de uma exceção específica -> except no console.
    Resultado válido -> return de dados -> print no console.
    Operações sem resultado, como escrever e sair, retornam None implicitamente.
    Não misturamos mensagens de erro com dados retornados. As falhas dos testes
    são registradas pelo unittest; o console captura somente os erros esperados.

ESCOPO DO EXERCÍCIO
    Biblioteca padrão: ABC, unittest, argparse, getpass, hashlib, hmac e secrets.
    As credenciais armazenam hash PBKDF2-HMAC-SHA256 com salt aleatório por conta.
    getpass oculta a digitação das senhas quando executado em um terminal.
    Execução local e armazenamento somente em memória. Contas
    e documento são descartados ao encerrar o programa. O documento é compartilhado
    entre as contas da mesma execução. Não há integração com o aplicativo Android.
    A escolha do perfil no cadastro é um recurso didático. Em um serviço público,
    perfis privilegiados precisam ser concedidos por uma autoridade administrativa.
    Aqui distinguimos login inexistente e senha incorreta para demonstrar erros;
    em uma API pública, a resposta deve ser genérica para não revelar contas.
    Este exercício não implementa persistência, recuperação de senha, limitação
    de tentativas ou sessões distribuídas.

As etapas numeradas abaixo substituem os módulos de um projeto maior.
"""

import argparse
import hashlib
import hmac
import io
import secrets
import unittest
from abc import ABC, abstractmethod
from getpass import getpass


# ============================================================================
# ETAPA 1 — Exceções: os erros fazem parte do contrato das operações.
# ============================================================================


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


# ============================================================================
# ETAPA 2 — Validação e vocabulário do domínio.
# ============================================================================


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


# ============================================================================
# ETAPA 3 — Composição, herança, abstração e polimorfismo.
# ============================================================================


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


# ============================================================================
# ETAPA 4 — Interface de armazenamento e sua implementação em memória.
# ============================================================================


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


class RepositorioUsuariosEmMemoria(RepositorioUsuarios):
    def __init__(self) -> None:
        self.__usuarios: dict[str, Usuario] = {}

    def adicionar(self, usuario: Usuario) -> None:
        if usuario.login in self.__usuarios:
            raise LoginJaCadastrado("Este login já está cadastrado. Escolha outro.")
        self.__usuarios[usuario.login] = usuario

    def buscar(self, login: str) -> Usuario | None:
        return self.__usuarios.get(login)


# ============================================================================
# ETAPA 5 — Recurso protegido: leitura e escrita reais de um texto em memória.
# ============================================================================


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


# ============================================================================
# ETAPA 6 — Serviço: cadastro, autenticação, sessão e autorização.
# ============================================================================


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


# ============================================================================
# ETAPA 7 — Apresentação: input, getpass, print e tratamento dos erros esperados.
# ============================================================================


class AplicacaoConsole:
    def __init__(
        self, servico: ServicoLogin, ler=input, mostrar=print, ler_senha=getpass
    ) -> None:
        self.__servico = servico
        # Funções recebidas permitem testar a interação sem bibliotecas de mock.
        self.__ler = ler
        self.__ler_senha = ler_senha
        self.__mostrar = mostrar

    def executar(self) -> None:
        self.__mostrar("\nSISTEMA DE LOGIN — EXERCÍCIO DE POO COM IMPORTAÇÕES")
        self.__mostrar("Os dados desta execução ficam somente na memória.")
        while True:
            acoes = self.__montar_menu()
            for opcao, (rotulo, _) in acoes.items():
                self.__mostrar(f"{opcao} — {rotulo}")
            self.__mostrar("0 — Encerrar programa")
            opcao = self.__ler("Escolha: ").strip()
            if opcao == "0":
                self.__servico.sair()
                self.__mostrar("Programa encerrado.")
                return
            if opcao not in acoes:
                self.__mostrar("Erro: opção inválida. Escolha uma opção do menu.")
                continue
            _, acao = acoes[opcao]
            try:
                acao()
            except ErroAplicacao as erro:
                self.__mostrar(f"Erro: {erro}")

    def __montar_menu(self) -> dict:
        usuario = self.__servico.usuario_atual
        if usuario is None:
            self.__mostrar("\n--- ACESSO ---")
            return {
                "1": ("Criar login", self.__cadastrar),
                "2": ("Entrar", self.__entrar),
                "3": ("Executar testes", self.__testar),
                "4": ("Feedback sobre o uso da IA", self.__feedback),
            }
        permissoes = ", ".join(sorted(usuario.permissoes))
        self.__mostrar(f"\n--- CONTA: {usuario.login} | CLASSE: {type(usuario).__name__} ---")
        self.__mostrar(f"Perfil: {usuario.perfil} | Permissões: {permissoes}")
        return {
            "1": ("Ler documento", self.__ler_documento),
            "2": ("Escrever documento (substituir texto)", self.__escrever),
            "3": ("Sair da conta", self.__sair),
        }

    def __escolher_perfil(self) -> str:
        opcoes = dict(enumerate(Perfil.TODOS, start=1))
        for numero, perfil in opcoes.items():
            self.__mostrar(f"{numero} — {perfil}")
        try:
            return opcoes[int(self.__ler("Perfil para o exercício: "))]
        except (ValueError, KeyError) as erro:
            raise PerfilInvalido("Perfil inválido. Escolha 1, 2 ou 3.") from erro

    def __cadastrar(self) -> None:
        self.__mostrar("\n--- CRIAÇÃO DE LOGIN ---")
        self.__mostrar("Login: 3–30 caracteres. Senha: 12–128 caracteres, oculta no terminal.")
        login = self.__ler("Novo login: ")
        senha = self.__ler_senha("Nova senha: ")
        confirmacao = self.__ler_senha("Confirme a senha: ")
        perfil = self.__escolher_perfil()
        usuario = self.__servico.cadastrar(login, senha, confirmacao, perfil)
        self.__mostrar(f"Conta '{usuario.login}' criada como {usuario.perfil}. Agora entre.")

    def __entrar(self) -> None:
        login = self.__ler("Login: ")
        senha = self.__ler_senha("Senha: ")
        usuario = self.__servico.autenticar(login, senha)
        self.__mostrar(f"Login realizado. Bem-vindo(a), {usuario.login}!")

    def __ler_documento(self) -> None:
        conteudo = self.__servico.ler_documento()
        self.__mostrar(f"\n--- DOCUMENTO ---\n{conteudo}")

    def __escrever(self) -> None:
        conteudo = self.__ler("Novo conteúdo (uma linha): ")
        self.__servico.escrever_documento(conteudo)
        self.__mostrar("Documento atualizado com sucesso.")

    def __sair(self) -> None:
        self.__servico.sair()
        self.__mostrar("Você saiu da conta.")

    def __testar(self) -> None:
        if not executar_testes(self.__mostrar):
            self.__mostrar("Existem falhas nos testes; confira os casos indicados.")

    def __feedback(self) -> None:
        self.__mostrar(FEEDBACK_IA)


# ============================================================================
# ETAPA 8 — Montagem: dependências criadas em um único ponto.
# ============================================================================


def criar_aplicacao(ler=input, mostrar=print, ler_senha=getpass) -> AplicacaoConsole:
    repositorio = RepositorioUsuariosEmMemoria()
    servico = ServicoLogin(repositorio)
    return AplicacaoConsole(servico, ler, mostrar, ler_senha)


# ============================================================================
# ETAPA 9 — Testes independentes com unittest e console simulado.
# ============================================================================

class TestesValidacao(unittest.TestCase):
    def test_login_normalizado(self) -> None:
        self.assertTrue(ValidadorEntrada.normalizar_login("  Joao_01  ") == "joao_01")

    def test_login_invalido(self) -> None:
        for login in ("", "ab", "1joao", "jo ao", "joão", "a" * 31, None):
            self.assertRaises(LoginInvalido, ValidadorEntrada.normalizar_login, login)

    def test_senha_invalida(self) -> None:
        for senha in ("", "curta", " " * 12, "a" * 129, None):
            self.assertRaises(SenhaInvalida, ValidadorEntrada.validar_senha_cadastro, senha)

    def test_limites_validos(self) -> None:
        for login in ("abc", "a" * 30):
            self.assertTrue(ValidadorEntrada.normalizar_login(login) == login)
        for tamanho in (12, 128):
            ValidadorEntrada.validar_senha_cadastro("a" * tamanho)

    def test_credencial_preserva_acentos_e_espacos(self) -> None:
        senha = "  Entrada fictícia de teste  "
        credencial = Credencial(senha)
        self.assertTrue(credencial.confere(senha))
        self.assertTrue(not credencial.confere(senha.strip()))

    def test_usuario_base_exige_subclasse(self) -> None:
        self.assertRaises(TypeError, Usuario, "teste", "Entrada fictícia de teste")

    def test_interface_exige_implementacao_dos_metodos(self) -> None:
        self.assertRaises(TypeError, RepositorioUsuarios)

        class RepositorioIncompleto(RepositorioUsuarios):
            def buscar(self, login: str) -> Usuario | None:
                return None

        # Falta implementar adicionar: ABC impede criar esse repositório.
        self.assertRaises(TypeError, RepositorioIncompleto)

    def test_credenciais_iguais_recebem_salts_e_hashes_diferentes(self) -> None:
        senha = "Entrada fictícia de teste"
        primeira = Credencial(senha)
        segunda = Credencial(senha)
        # Inspeção interna intencional: verifica a forma de armazenamento.
        self.assertNotEqual(primeira._Credencial__salt, segunda._Credencial__salt)
        self.assertNotEqual(primeira._Credencial__hash, segunda._Credencial__hash)
        self.assertNotIn(senha, vars(primeira).values())
        self.assertTrue(primeira.confere(senha))
        self.assertTrue(segunda.confere(senha))


class TestesSistemaLogin(unittest.TestCase):
    SENHA_TESTE = "Entrada fictícia de teste"

    def setUp(self) -> None:
        # unittest prepara um estado novo antes de cada caso.
        self.repositorio = RepositorioUsuariosEmMemoria()
        self.usuarios = {}
        for indice, perfil in enumerate(Perfil.TODOS, start=1):
            usuario = criar_usuario(f"conta_{indice}", self.SENHA_TESTE, perfil)
            self.usuarios[perfil] = usuario
            self.repositorio.adicionar(usuario)
        self.servico = ServicoLogin(self.repositorio)

    def entrar(self, perfil: str) -> Usuario:
        return self.servico.autenticar(self.usuarios[perfil].login, self.SENHA_TESTE)

    def test_cadastro_cria_as_tres_classes(self) -> None:
        classes = (UsuarioLeitor, UsuarioEscritor, UsuarioLeitorEscritor)
        for indice, (perfil, classe) in enumerate(zip(Perfil.TODOS, classes)):
            usuario = self.servico.cadastrar(
                f"novo_{indice}", self.SENHA_TESTE, self.SENHA_TESTE, perfil
            )
            self.assertTrue(isinstance(usuario, classe))
            self.assertTrue(self.repositorio.buscar(usuario.login) is usuario)
        self.assertTrue(self.servico.usuario_atual is None)

    def test_cadastro_duplicado_preserva_usuario(self) -> None:
        original = self.usuarios[Perfil.LEITOR]
        self.assertRaises(
            LoginJaCadastrado, self.servico.cadastrar,
            f" {original.login.upper()} ", self.SENHA_TESTE, self.SENHA_TESTE,
            Perfil.LEITOR_ESCRITOR,
        )
        self.assertTrue(self.repositorio.buscar(original.login) is original)

    def test_repositorio_impede_sobrescrita(self) -> None:
        self.assertRaises(
            LoginJaCadastrado, self.repositorio.adicionar, self.usuarios[Perfil.LEITOR]
        )

    def test_confirmacao_incorreta_nao_cria_conta(self) -> None:
        self.assertRaises(
            ConfirmacaoSenhaInvalida, self.servico.cadastrar,
            "novo", self.SENHA_TESTE, "diferente", Perfil.LEITOR,
        )
        self.assertTrue(self.repositorio.buscar("novo") is None)

    def test_perfil_invalido_nao_cria_conta(self) -> None:
        for perfil in ("admin", None, [], 99):
            self.assertRaises(
                PerfilInvalido, self.servico.cadastrar,
                "novo", self.SENHA_TESTE, self.SENHA_TESTE, perfil,
            )
            self.assertTrue(self.repositorio.buscar("novo") is None)

    def test_login_invalido_nao_cria_conta(self) -> None:
        self.assertRaises(
            LoginInvalido, self.servico.cadastrar,
            "x", self.SENHA_TESTE, self.SENHA_TESTE, Perfil.LEITOR,
        )
        self.assertTrue(self.repositorio.buscar("x") is None)

    def test_senha_curta_nao_cria_conta(self) -> None:
        self.assertRaises(
            SenhaInvalida, self.servico.cadastrar, "novo", "curta", "curta", Perfil.LEITOR
        )
        self.assertTrue(self.repositorio.buscar("novo") is None)

    def test_login_valido_abre_sessao(self) -> None:
        esperado = self.usuarios[Perfil.LEITOR]
        recebido = self.servico.autenticar(f" {esperado.login.upper()} ", self.SENHA_TESTE)
        self.assertTrue(recebido is esperado)
        self.assertTrue(self.servico.usuario_atual is esperado)

    def test_login_inexistente_nao_abre_sessao(self) -> None:
        self.assertRaises(
            UsuarioNaoEncontrado, self.servico.autenticar, "ausente", self.SENHA_TESTE
        )
        self.assertTrue(self.servico.usuario_atual is None)

    def test_senha_incorreta_nao_abre_sessao(self) -> None:
        self.assertRaises(
            SenhaIncorreta, self.servico.autenticar,
            self.usuarios[Perfil.LEITOR].login, "incorreta",
        )
        self.assertTrue(self.servico.usuario_atual is None)

    def test_login_rejeita_entradas_vazias(self) -> None:
        self.assertRaises(LoginInvalido, self.servico.autenticar, "", self.SENHA_TESTE)
        self.assertRaises(SenhaInvalida, self.servico.autenticar, "conta_1", "")
        self.assertTrue(self.servico.usuario_atual is None)

    def test_novo_login_exige_logout(self) -> None:
        atual = self.entrar(Perfil.LEITOR)
        self.assertRaises(SessaoJaAutenticada, self.entrar, Perfil.LEITOR_ESCRITOR)
        self.assertTrue(self.servico.usuario_atual is atual)

    def test_sem_login_nao_le_nem_escreve(self) -> None:
        self.assertRaises(SessaoNaoAutenticada, self.servico.ler_documento)
        self.assertRaises(
            SessaoNaoAutenticada, self.servico.escrever_documento, "Sem autenticação"
        )

    def test_leitor_nao_altera_documento(self) -> None:
        self.entrar(Perfil.LEITOR)
        anterior = self.servico.ler_documento()
        self.assertRaises(PermissaoNegada, self.servico.escrever_documento, "Alteração")
        self.assertTrue(self.servico.ler_documento() == anterior)

    def test_escritor_escreve_mas_nao_le(self) -> None:
        self.entrar(Perfil.ESCRITOR)
        self.servico.escrever_documento("Texto produzido pelo escritor.")
        self.assertRaises(PermissaoNegada, self.servico.ler_documento)
        self.servico.sair()
        self.entrar(Perfil.LEITOR)
        self.assertTrue(self.servico.ler_documento() == "Texto produzido pelo escritor.")

    def test_leitor_escritor_realiza_as_duas_operacoes(self) -> None:
        self.entrar(Perfil.LEITOR_ESCRITOR)
        self.servico.escrever_documento("Texto revisado.")
        self.assertTrue(self.servico.ler_documento() == "Texto revisado.")

    def test_conteudo_invalido_preserva_documento(self) -> None:
        self.entrar(Perfil.LEITOR_ESCRITOR)
        anterior = self.servico.ler_documento()
        for conteudo in ("", "   ", "x" * 5_001, None):
            self.assertRaises(ConteudoInvalido, self.servico.escrever_documento, conteudo)
            self.assertTrue(self.servico.ler_documento() == anterior)

    def test_documento_aceita_limite_e_preserva_espacos(self) -> None:
        self.entrar(Perfil.LEITOR_ESCRITOR)
        texto = " " + "x" * 4_998 + " "
        self.servico.escrever_documento(texto)
        self.assertTrue(self.servico.ler_documento() == texto)

    def test_logout_remove_acesso_e_pode_ser_repetido(self) -> None:
        self.entrar(Perfil.LEITOR_ESCRITOR)
        self.servico.sair()
        self.servico.sair()
        self.assertTrue(self.servico.usuario_atual is None)
        self.assertRaises(SessaoNaoAutenticada, self.servico.ler_documento)
        self.assertRaises(SessaoNaoAutenticada, self.servico.escrever_documento, "Texto")

    def test_agregacao_compartilha_repositorio_mas_nao_sessao(self) -> None:
        outro = ServicoLogin(self.repositorio)
        self.entrar(Perfil.LEITOR_ESCRITOR)
        self.servico.escrever_documento("Documento exclusivo do primeiro serviço.")
        self.assertTrue(outro.usuario_atual is None)
        usuario = outro.autenticar(self.usuarios[Perfil.LEITOR].login, self.SENHA_TESTE)
        self.assertTrue(usuario is self.usuarios[Perfil.LEITOR])
        self.assertTrue(outro.ler_documento() != self.servico.ler_documento())


class ConsoleSimulado:
    """Entradas e saídas de teste, sem teclado, impressão ou alteração de globais."""

    def __init__(self, entradas: list) -> None:
        self.__entradas = iter(entradas)
        self.mensagens: list[str] = []

    def ler(self, mensagem: str) -> str:
        self.mostrar(mensagem)
        try:
            entrada = next(self.__entradas)
        except StopIteration:
            raise EOFError("As entradas simuladas terminaram.") from None
        if isinstance(entrada, (EOFError, KeyboardInterrupt)):
            raise entrada
        return entrada

    def mostrar(self, mensagem: str) -> None:
        self.mensagens.append(mensagem)

    @property
    def texto(self) -> str:
        return "\n".join(self.mensagens)


class TestesConsole(unittest.TestCase):
    def test_opcao_invalida_mantem_menu(self) -> None:
        console = ConsoleSimulado(["99", "0"])
        criar_aplicacao(console.ler, console.mostrar, console.ler).executar()
        self.assertTrue("opção inválida" in console.texto)
        self.assertTrue("Programa encerrado." in console.texto)

    def test_perfil_invalido_nao_cria_conta(self) -> None:
        senha = TestesSistemaLogin.SENHA_TESTE
        for opcao in ("abc", "9"):
            repositorio = RepositorioUsuariosEmMemoria()
            console = ConsoleSimulado(["1", "novo", senha, senha, opcao, "0"])
            AplicacaoConsole(
                ServicoLogin(repositorio), console.ler, console.mostrar, console.ler
            ).executar()
            self.assertTrue("Perfil inválido" in console.texto)
            self.assertTrue(repositorio.buscar("novo") is None)

    def test_fluxo_completo_cadastro_login_escrita_leitura_logout(self) -> None:
        senha = TestesSistemaLogin.SENHA_TESTE
        console = ConsoleSimulado([
            "1", "novo", senha, senha, "3",
            "2", "novo", senha,
            "2", "Texto pelo menu.", "1", "3", "0",
        ])
        criar_aplicacao(console.ler, console.mostrar, console.ler).executar()
        for mensagem in (
            "criada", "Login realizado", "UsuarioLeitorEscritor",
            "atualizado com sucesso", "Texto pelo menu.", "saiu da conta",
        ):
            self.assertTrue(mensagem in console.texto, f"Mensagem ausente: {mensagem}")
        self.assertTrue(senha not in console.texto, "Uma resposta repetiu a senha digitada.")

    def test_login_inexistente_mostra_erro_e_continua(self) -> None:
        console = ConsoleSimulado(["2", "ausente", TestesSistemaLogin.SENHA_TESTE, "0"])
        criar_aplicacao(console.ler, console.mostrar, console.ler).executar()
        self.assertTrue("Login não encontrado" in console.texto)
        self.assertTrue("Programa encerrado." in console.texto)

    def test_senha_incorreta_permite_tentar_novamente(self) -> None:
        senha = TestesSistemaLogin.SENHA_TESTE
        console = ConsoleSimulado([
            "1", "novo", senha, senha, "1",
            "2", "novo", "incorreta", "2", "novo", senha, "0",
        ])
        criar_aplicacao(console.ler, console.mostrar, console.ler).executar()
        self.assertTrue("Senha incorreta" in console.texto)
        self.assertTrue("Login realizado" in console.texto)

    def test_permissao_negada_e_tratada_no_menu(self) -> None:
        senha = TestesSistemaLogin.SENHA_TESTE
        console = ConsoleSimulado([
            "1", "leitor", senha, senha, "1",
            "2", "leitor", senha, "2", "Tentativa de alteração", "1", "0",
        ])
        criar_aplicacao(console.ler, console.mostrar, console.ler).executar()
        self.assertTrue("Acesso negado" in console.texto)
        self.assertTrue("Este é o documento compartilhado" in console.texto)

    def test_feedback_disponivel_no_menu(self) -> None:
        console = ConsoleSimulado(["4", "0"])
        criar_aplicacao(console.ler, console.mostrar, console.ler).executar()
        self.assertTrue("IA utilizada: Codex" in console.texto)

    def test_senhas_usam_leitor_separado_do_input(self) -> None:
        console = ConsoleSimulado(["1", "novo", "1", "2", "novo", "0"])
        senhas = iter([TestesSistemaLogin.SENHA_TESTE] * 3)
        solicitacoes = []

        def ler_senha(mensagem: str) -> str:
            solicitacoes.append(mensagem)
            return next(senhas)

        criar_aplicacao(console.ler, console.mostrar, ler_senha).executar()
        self.assertEqual(len(solicitacoes), 3)
        self.assertIn("Login realizado", console.texto)

    def test_main_trata_interrupcao_e_fim_de_entrada(self) -> None:
        for interrupcao in (EOFError(), KeyboardInterrupt()):
            console = ConsoleSimulado([interrupcao])
            self.assertTrue(main([], console.ler, console.mostrar, console.ler) == 0)
            self.assertTrue("Entrada interrompida" in console.texto)


def executar_testes(mostrar=print) -> bool:
    """unittest executa cada caso isoladamente; retorna True se todos passarem."""
    carregador = unittest.TestLoader()
    suite = unittest.TestSuite(
        carregador.loadTestsFromTestCase(grupo)
        for grupo in (TestesValidacao, TestesSistemaLogin, TestesConsole)
    )
    saida = io.StringIO()
    resultado = unittest.TextTestRunner(stream=saida, verbosity=2).run(suite)
    mostrar(saida.getvalue().rstrip())
    return resultado.wasSuccessful()


# ============================================================================
# ETAPA 10 — Feedback exigido na atividade.
# ============================================================================


FEEDBACK_IA = """FEEDBACK SOBRE O USO DE IA

IA utilizada: Codex, da OpenAI.
Forma de acesso: conversa em linguagem natural no aplicativo Codex, com acesso
à pasta do projeto, edição do arquivo e execução dos testes pelo terminal.

Linguagem: Python 3.10 ou superior. Esta versão usa somente a biblioteca padrão.
Técnicas: programação orientada a objetos, interface com ABC/abstractmethod,
herança, polimorfismo, encapsulamento, agregação, composição, fábrica simples
e injeção de dependência. ABC impede instanciar implementações incompletas.

Organização: cada classe tem uma responsabilidade. O serviço usa return para
dados e raise para erros. O console usa try/except, input, getpass e print.
As permissões são verificadas no serviço antes de cada leitura e escrita.

Credenciais: PBKDF2-HMAC-SHA256 com 600.000 iterações e salt aleatório por conta;
hmac.compare_digest compara os hashes. A credencial não guarda a senha em texto
puro e getpass oculta a digitação em um terminal.

Testes: unittest, com estado independente em cada caso, verifica validação,
cadastro, autenticação, sessão, permissões e console. Há testes específicos
para o contrato abstrato e o armazenamento das credenciais.

Limite didático: contas e documento ficam em memória e desaparecem ao encerrar.
O perfil é escolhido no cadastro para demonstrar as três classes de usuário.
Não há persistência, recuperação de senha ou limitação de tentativas.

Técnica de interação com a IA: requisitos em linguagem natural, divisão por
responsabilidade e validação automatizada das duas versões solicitadas.

Execução: a opção 3 do menu inicial ou --testes executa os testes; a opção 4
ou --feedback mostra este relato. Não é necessário instalar pacotes com pip.

Dificuldade de entendimento e autoavaliação do aluno:
Meu nível de dificuldade foi baixo. Foi fácil compreender o trabalho, pois já
estou habituado a utilizar inteligência artificial no desenvolvimento dos meus
projetos. Essa familiaridade me ajuda a formular os pedidos, acompanhar as
respostas e solicitar ajustes conforme os objetivos da atividade.

Neste exercício, defini os requisitos de POO, a divisão de responsabilidades,
o tratamento de erros e a necessidade de testes. Esclareci a restrição de não
usar imports e, depois, pedi duas versões independentes para comparar as
abordagens. Também solicitei a verificação das duas implementações. A IA apoiou
a escrita e a execução dos testes, enquanto eu conduzi os requisitos e as
revisões da entrega.

Observação da IA sobre a participação do aluno:
Nas interações deste exercício, o aluno apresentou critérios concretos para
o código, revisou a solução proposta e corrigiu o rumo quando identificou uma
diferença em relação ao que pretendia. Os pedidos de baixo acoplamento,
responsabilidades bem definidas, tratamento de erros e testes demonstram
atenção à organização e ao funcionamento do projeto. A solicitação das duas
versões e de sua verificação também mostra interesse em comparar soluções
e conferir o resultado produzido com apoio da IA.
"""


# ============================================================================
# ETAPA 11 — main e ponto de entrada padrão.
# ============================================================================


def main(argumentos=None, ler=input, mostrar=print, ler_senha=getpass) -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
