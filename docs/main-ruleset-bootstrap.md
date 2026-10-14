# Bootstrap protegido do ruleset da main

O objetivo é criar uma única vez `agent-core-main-governed` no repositório público `ericson-j-santos/agent-core`, usando exatamente `.github/rulesets/agent-core-main.json`. A PR de bootstrap executa somente no contexto de branch pertencente ao repositório e iniciada pelo proprietário. Não faz deploy, não altera outros repositórios e não aceita destinos externos.

## Pré-condição administrativa não delegável ao chat

O token automático `GITHUB_TOKEN` não possui permissão `Administration: write`. Autorize uma credencial de curta duração diretamente no GitHub:

1. Em **Settings → Developer settings → Personal access tokens → Fine-grained tokens**, escolha o proprietário da conta e selecione **Only select repositories → agent-core**.
2. Permissões: somente **Repository permissions → Administration: Read and write** (mais Metadata: read, concedido pela plataforma). Use uma expiração curta, de preferência 7 dias.
3. Sem colar o token no chat, salve-o como **Actions repository secret** chamado `AGENT_CORE_RULESET_ADMIN_TOKEN` em [Secrets and variables → Actions](https://github.com/ericson-j-santos/agent-core/settings/secrets/actions).
4. Depois de criar o segredo, produza um evento **novo** de PR editando a descrição da PR de bootstrap (ou solicite essa edição no ChatGPT com a conexão GitHub). Isso cria uma execução com o segredo disponível; reexecutar um job antigo pode reutilizar o estado da execução original. O código reavalia o estado e não duplica a regra.

O token só é lido pelo job confiável `owner-authorized-bootstrap`, condicionado à conta proprietária, à branch `feat/main-ruleset-bootstrap-20261014`, a PR interna e à base `main`. O job executa **GETs**, um único **POST** ao endpoint de rulesets quando a regra não existe, e mais GETs para conferir os atributos; não existe caminho de PUT/DELETE, nem host ou repo dinâmico.

## Homologação e rotação

- Revalidar o HEAD da main após criação, listar o único ruleset ativo e exigir `agent-core-test`, pull request e restrições contra force-push/deleção, sem bypass; o auditor independente `scripts/audit_main_governance.py` confirma as regras efetivas.
- Distinguir testes simulados no CI de criação real de regra. Uma resposta HTTP 201 não basta: exigir leitura independente do estado persistido no GitHub.
- Provar enforcement com teste negativo seguro antes de declarar padrão ouro.
- Revogue o token de bootstrap após comprovar a proteção. A rotina diária já existente detecta possíveis perdas de governança sem precisar conservar a credencial privilegiada.
- **Falha de credencial/escopo/HEAD ou regra inesperada:** parar com código não zero, preservar main e relatar o motivo sanitizado. Não criar outro ruleset, não contornar a proteção por merge direto.

O bootstrap é uma exceção operacional de instalação **somente na PR**, não um runtime ou fila nova. Não colocar token, link de credencial ou dados privados em arquivos, issues ou logs.


## Credencial de leitura da auditoria diária

O GitHub Actions `GITHUB_TOKEN` padrão pode ocultar `bypass_actors` de
rulesets. Em 14/10/2026, o run pós-merge #38602988869 comprovou
`ruleset_bypass_unverifiable` com o token padrão, embora o ruleset ativo
já estivesse no servidor. **Não tratar ausência desse campo como lista vazia.**

A auditoria `main-server-ruleset-audit` usa temporariamente o segredo
`AGENT_CORE_RULESET_ADMIN_TOKEN` **somente em requisições GET**, e somente
nos eventos `push main`, `schedule` e `workflow_dispatch`. O teste da
PR `governance-contract-tests` não recebe esse segredo. O script nunca
realiza POST, PUT, PATCH ou DELETE.

A credencial temporária expirará segundo a validade concedida pelo
proprietário; a auditoria falhará fechada depois disso. A solução permanente
é uma identidade GitHub App com permissão `Administration: read` restrita
ao mesmo repositório, emitindo tokens temporários sem reusar a permissão
de escrita do bootstrap. Até essa transição ser homologada, **não apagar
o segredo sem aceitar que a auditoria ficará vermelha**. A revogação da
permissão de escrita é uma ação administrativa externa a este pacote.
