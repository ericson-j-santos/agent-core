# Bootstrap protegido do ruleset da main

O objetivo é criar uma única vez `agent-core-main-governed` no repositório público `ericson-j-santos/agent-core`, usando exatamente `.github/rulesets/agent-core-main.json`. A PR de bootstrap executa somente no contexto de branch pertencente ao repositório e iniciada pelo proprietário. Não faz deploy, não altera outros repositórios e não aceita destinos externos.

## Pré-condição administrativa não delegável ao chat

O token automático `GITHUB_TOKEN` não possui permissão `Administration: write`. Autorize uma credencial de curta duração diretamente no GitHub:

1. Em **Settings → Developer settings → Personal access tokens → Fine-grained tokens**, escolha o proprietário da conta e selecione **Only select repositories → agent-core**.
2. Permissões: somente **Repository permissions → Administration: Read and write** (mais Metadata: read, concedido pela plataforma). Use uma expiração curta, de preferência 7 dias.
3. Sem colar o token no chat, salve-o como **Actions repository secret** chamado `AGENT_CORE_RULESET_ADMIN_TOKEN` em [Secrets and variables → Actions](https://github.com/ericson-j-santos/agent-core/settings/secrets/actions).
4. Execute novamente o job da PR de bootstrap após a criação do segredo, caso a primeira tentativa tenha falhado por ausência de credencial. O código reavalia o estado e não duplica a regra.

O token só é lido pelo job confiável `owner-authorized-bootstrap`, condicionado à conta proprietária, à branch `feat/main-ruleset-bootstrap-20261014`, a PR interna e à base `main`. O job executa **GETs**, um único **POST** ao endpoint de rulesets quando a regra não existe, e mais GETs para conferir os atributos; não existe caminho de PUT/DELETE, nem host ou repo dinâmico.

## Homologação e rotação

- Revalidar o HEAD da main após criação, listar o único ruleset ativo e exigir `agent-core-test`, pull request e restrições contra force-push/deleção, sem bypass; o auditor independente `scripts/audit_main_governance.py` confirma as regras efetivas.
- Distinguir testes simulados no CI de criação real de regra. Uma resposta HTTP 201 não basta: exigir leitura independente do estado persistido no GitHub.
- Provar enforcement com teste negativo seguro antes de declarar padrão ouro.
- Revogue o token de bootstrap após comprovar a proteção. A rotina diária já existente detecta possíveis perdas de governança sem precisar conservar a credencial privilegiada.
- **Falha de credencial/escopo/HEAD ou regra inesperada:** parar com código não zero, preservar main e relatar o motivo sanitizado. Não criar outro ruleset, não contornar a proteção por merge direto.

O bootstrap é uma exceção operacional de instalação **somente na PR**, não um runtime ou fila nova. Não colocar token, link de credencial ou dados privados em arquivos, issues ou logs.
