from getpass import getpass
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
from login_poo.domain.models import Perfil
from login_poo.application.service import ServicoLogin

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
        from login_poo.selftest import executar_testes
        if not executar_testes(self.__mostrar):
            self.__mostrar("Existem falhas nos testes; confira os casos indicados.")

    def __feedback(self) -> None:
        self.__mostrar(FEEDBACK_IA)
