# Portas e adaptadores

```text
presentation/console → application/service → domain
                              ↓
                       application/ports
                              ↑
                     infrastructure/memory
```

`bootstrap.py` monta as dependências. O serviço recebe o contrato do repositório
e não conhece armazenamento concreto nem entrada/saída. Entidades e permissões
concentram regras; subclasses implementam os perfis. As exceções são contratos
de falha. O console converte entrada e apresenta os resultados.

As suítes originais foram preservadas em `selftest.py` para permitir os testes
do menu didático e a descoberta pelo unittest. Verificam cadastro duplicado,
sessões, permissões, validação, hashes e interação simulada. A organização foi
feita sobre código existente; não se afirma que o histórico seguiu TDD.
