# Login POO em Python

Sistema local de cadastro, login, sessão e documento compartilhado com perfis
leitor, escritor e leitor/escritor. Biblioteca padrão; Python 3.10+.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m login_poo
.venv/bin/python -m unittest discover -s tests -v
```

As versões independentes do exercício, com e sem imports, estão em `examples/`.
A versão sem imports guarda credenciais apenas em memória e serve para mostrar
a restrição da atividade; não oferece armazenamento seguro de senhas.
A versão modular usa PBKDF2 com salt aleatório e entrada oculta no terminal.

O cadastro permite escolher perfis para demonstrar polimorfismo. Não há API,
persistência, recuperação de conta ou limitação de tentativas. Não implante o
exercício como serviço de autenticação público.

Veja [arquitetura](docs/architecture.md) e [segurança](SECURITY.md).
