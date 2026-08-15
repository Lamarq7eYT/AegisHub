# Hipótese 2 — fronteira de escrita em workflow privado próprio

## Pergunta

Um actor `researcher`, autenticado por uma conta própria e sem acesso ao laboratório privado, consegue atualizar o arquivo fixo `.github/workflows/aegishub-boundary-probe.yml` por meio da operação Contents `PUT`, usando uma capacidade de workflow do GitHub App que deveria respeitar a autorização efetiva do usuário?

## Por que esta hipótese é elegível

O target oficial GitHub API inclui escalada de privilégio por GitHub Apps/OAuth Apps e acesso indevido a recursos privados. O teste usa somente um repositório privado próprio, duas contas controladas e conteúdo sintético. A operação é read/write de baixo volume, não executa workflow, não acessa segredo e não tenta aumentar o impacto.

## Propriedade de segurança

Somente o owner verificado do laboratório pode alterar o workflow probe fixo. O researcher deve receber uma negação e o owner deve continuar lendo o marcador intacto. Uma resposta de sucesso para o researcher, acompanhada de confirmação mínima pelo owner e sem explicação benigna de permissão, seria um candidato de integridade de baixo escopo para revisão humana.

## Desenho mínimo

O plano executa, em série, owner baseline read, researcher update do workflow probe com payload fixo e harmless, owner repeat read e uma leitura anonymous de controle. O update não executa o workflow, não acessa segredos e não usa branch ou path arbitrários. Se a mutation researcher for aceita, o runner aciona candidate-stop e o cleanup owner exclui o workflow probe usando o SHA retornado pelo commit. Se a mutation for negada, o owner repeat confirma que o marcador permanece disponível.

## Budgets e travas

O plano usa no máximo 4 operações observáveis, concorrência 1, zero operações fora do catálogo, uma mutation potencial do researcher, cleanup obrigatório se uma mutation for aplicada, terminal interativo e approval grant. Não há branch arbitrário, caminho arbitrário, mensagem arbitrária ou conteúdo arbitrário: todos são fixados no catálogo e no manifesto do laboratório.

## Critérios

`expected` significa researcher negado e owner repeat com marcador protegido. `anomalous` significa researcher mutation com resposta de sucesso e evidência de commit/write, sem depender apenas de status ou mensagem; a confirmação owner é somente a mínima necessária para verificar o estado do próprio laboratório. `inconclusive` cobre rate-limit, policy block, resposta transitória, marker inconsistente ou ausência de confirmação. `dirty` bloqueia a continuação até cleanup resolvido. Nenhum resultado recebe severidade automática.

## Parada e divulgação

Ao primeiro sucesso de escrita pelo researcher, o runner para antes de qualquer operação posterior, executa apenas cleanup obrigatório e grava evidência sanitizada. O resultado seria entregue como **“Candidato de segurança — aguardando revisão humana.”** Não haverá submissão, publicação, acesso a terceiros, segredo, workflow execution ou cadeia adicional.

## Fontes

- https://bounty.github.com/targets/github-api.html
- https://bounty.github.com/rules.html
- https://bounty.github.com/ineligible.html
- https://docs.github.com/en/rest/repos/contents#update-a-file-contents
- https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app
