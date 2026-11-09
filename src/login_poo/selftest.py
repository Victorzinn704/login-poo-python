import io
import unittest
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
from login_poo.infrastructure.memory import RepositorioUsuariosEmMemoria
from login_poo.application.service import ServicoLogin
from login_poo.presentation.console import AplicacaoConsole, FEEDBACK_IA
from login_poo.bootstrap import criar_aplicacao
from login_poo.cli import main

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
