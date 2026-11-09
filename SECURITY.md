# Segurança

Não publique vulnerabilidades com credenciais em issues. Use a aba Security do
GitHub para relato privado, quando disponível.

## Fronteira pública

Código, testes com dados fictícios, documentação e `.env.example` sem valores
reais podem ser versionados. Arquivos `.env`, chaves, bancos, logs, tokens,
histórico de terminal, dados pessoais e modelos baixados ficam fora do Git.
Uma URL pública de API é configuração; credenciais e decisões de autorização
devem permanecer no servidor. Variáveis de frontend e APK não ocultam segredos.

## Antes de enviar

Instale Gitleaks 8.30.1 e execute:

```sh
gitleaks dir . --redact=100
gitleaks git . --redact=100 --log-opts="--all --full-history"
```

Ative o hook incluído com `git config core.hooksPath .githooks`.

Opcionalmente instale pre-commit e execute `pre-commit install`. Os hooks locais
podem ser ignorados; a verificação no CI é uma segunda barreira. Scanners não
garantem a ausência de todos os segredos. Revise também os arquivos do commit.

Se ocorrer exposição, revogue/rotacione primeiro no provedor, atualize os
consumidores e só depois coordene eventual limpeza de histórico. Apagar o
arquivo ou adicioná-lo ao `.gitignore` não revoga a credencial.

Referências: [GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
e [Gitleaks](https://github.com/gitleaks/gitleaks).
