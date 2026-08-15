# AegisHub Bounty Mode — Phase 2
## Consistência de autorização entre REST e GraphQL em recurso privado próprio

**Status:** especificação preparada para revisão humana; nenhuma implementação ou execução live autorizada por este documento.  
**Aprovado para desenho:** usuário do projeto, 2026-08-15.  
**Implementação:** pendente de aprovação separada.  
**Execução live:** proibida até que a implementação passe pelos gates locais e o usuário aprove uma sessão específica.

## 1. Objetivo e não-objetivos

Esta fase investiga uma única propriedade de segurança: **as interfaces REST e GraphQL devem aplicar uma fronteira equivalente de autorização quando consultam o mesmo conteúdo protegido de um repositório privado pertencente ao operador**. A investigação usará exclusivamente o repositório privado de laboratório já verificado, as contas owner/researcher controladas pelo operador e a perspectiva anonymous sem token.

O objetivo não é provar que uma diferença de formato, status ou mensagem seja uma vulnerabilidade. O objetivo é detectar, com normalização determinística e repetição mínima, se um ator sem acesso obtém os campos protegidos do marcador por uma interface enquanto a outra interface nega o acesso. A especificação evita metadata adicional para manter a hipótese estreita e o orçamento abaixo do teto da Phase 1.

Esta fase não inclui exploração genérica, URLs arbitrárias, introspecção GraphQL, consultas fornecidas pelo usuário, mutações de conteúdo, alterações de permissões, organizações, Apps/OAuth policy, SAML, Actions, Packages, Codespaces, SSRF, disponibilidade, timing, enumeração, scraping, brute force, PII ou dados de terceiros. Também não inclui submissão ao HackerOne, escolha automática de severidade ou divulgação pública.

A política oficial do GitHub destaca acesso a recursos privados sem autorização adequada e escalada via Apps/OAuth como áreas de foco da API [1]. A própria política exige contas próprias para testes de autorização e proíbe impacto em outros usuários [2]. O safe harbor não se estende automaticamente a terceiros e requer pesquisa de boa-fé consistente com a política [3].

## 2. Modelo de ameaça

O recurso protegido é o arquivo de marcador `.aegishub-lab.json` no repositório privado diretamente pertencente ao owner. O arquivo contém campos de controle da matrícula do laboratório e um nonce que deve permanecer fora das evidências públicas. O owner é autorizado; o researcher é uma identidade distinta, controlada pelo operador, sem acesso ao repositório; anonymous não possui token.

A propriedade de segurança é definida assim:

> Para o mesmo repositório privado e o mesmo conteúdo de marcador, somente o owner verificado pode receber os campos protegidos. Researcher e anonymous devem receber uma negação equivalente, ausência de objeto ou resposta sem os campos protegidos, independentemente de a consulta usar REST ou GraphQL.

Um possível defeito exige uma quebra repetível, sem explicação benigna suficiente, observada em pelo menos duas tentativas consistentes do mesmo ator e superfície. Uma resposta HTTP diferente, uma mensagem diferente, `null` GraphQL, ordenação, timestamp, request ID ou cabeçalho de rate limit não constituem candidato quando nenhum campo protegido é revelado.

O impacto, se houver candidato, será limitado ao marcador sintético do laboratório. A PoC não poderá acessar dados de usuários, conteúdo real de terceiros, segredos, PII ou qualquer repositório fora do manifesto.

## 3. Pré-condições

| Pré-condição | Verificação obrigatória |
| --- | --- |
| Política atual | `PolicyMonitor` deve confirmar freshness das fontes oficiais. A mudança de qualquer fonte bloqueia a execução. |
| Identidades | Owner e researcher devem ter IDs imutáveis diferentes; nenhuma credencial será compartilhada no chat, fixture ou relatório. |
| Laboratório | O manifesto deve apontar para o repositório privado diretamente owner-owned e para o marker SHA verificado. Rename com o mesmo ID pode ser reverificado; name reuse com outro ID bloqueia. |
| App | O App deve continuar restrito ao laboratório, com Device Flow, tokens expiráveis, sem webhooks, metadata read e contents read/write. Nenhuma permissão adicional pode ser presumida. |
| Catálogo | Todas as operações devem existir no catálogo fechado e usar documentos GraphQL checked-in. Não haverá query, endpoint ou host fornecido pelo YAML. |
| Estado | Não pode haver active run, dirty state, journal pendente ou política stale. |
| Execução | O teste live continuará opt-in, exigirá TTY e aprovação explícita; este documento não inicia essa etapa. |

Se qualquer pré-condição falhar, o resultado deve ser `policy_blocked`, `dirty` ou `inconclusive` conforme a causa, sem tentar contornar a trava.

## 4. Desenho experimental mínimo

A hipótese será testada somente com duas operações de leitura do mesmo marcador:

| Operação lógica | Superfície | Actor | Resultado permitido |
| --- | --- | --- | --- |
| Ler marcador do laboratório | REST Contents API | owner, researcher, anonymous | owner recebe marcador validado; não-owner recebe `403`/`404` sem campos protegidos |
| Ler marcador do laboratório | GraphQL API | owner, researcher, anonymous | owner recebe marcador validado; não-owner recebe `null`, erro de autorização ou resposta sem campos protegidos |

A operação GraphQL deverá ser um documento fixo, versionado no repositório e identificado por um `documentId` fechado. O documento pode consultar somente o repositório e o caminho fixos resolvidos do manifesto, retornar apenas os campos mínimos necessários para validar o marcador e não pode aceitar uma query, seleção, expressão, alias ou fragmento vindo do YAML. A expressão do caminho deve ser derivada internamente do marcador fixo; não haverá parâmetro de URL ou de expressão arbitrária.

O plano recomendado usa no máximo **12 requests**, mantendo os ceilings da Phase 1:

| Fase | Actor | Superfície | Tentativas | Objetivo |
| --- | --- | --- | ---: | --- |
| baseline | owner | REST e GraphQL | 1 por superfície | Confirmar que o marcador próprio é legível pelas duas interfaces. |
| repeat | owner | REST e GraphQL | 1 por superfície | Confirmar que a comparação owner permaneceu estável. |
| probe | researcher | REST e GraphQL | 2 por superfície | Procurar divulgação repetível fora da autorização. |
| probe | anonymous | REST e GraphQL | 2 por superfície | Confirmar a mesma fronteira para ausência de token. |

Isso totaliza 12 requests, concorrência 1, um request por segundo, burst máximo 2, timeout de 20 segundos, no máximo dois retries de leitura após a tentativa inicial somente quando a operação for classificada como safe-read e zero mutações. Se uma resposta transitória consumir o teto, o run não poderá aumentar o orçamento; deve terminar como `inconclusive` ou `policy_blocked` conforme o motivo.

A implementação deverá decidir explicitamente se um retry de leitura pertence à contagem de requests e documentar essa decisão no manifest. Nenhum retry poderá ser usado para transformar uma resposta ambígua em prova de impacto.

## 5. Catálogo fechado proposto

A extensão do catálogo deve ser mínima e revisar cada operação individualmente. A operação REST existente `github.rest.contents.get-lab-marker.v1` pode ser reutilizada se seu normalization profile e sua finalidade forem compatíveis. A nova operação GraphQL proposta é:

`github.graphql.contents.get-lab-marker.v1`

| Campo | Valor exigido |
| --- | --- |
| Protocol | `graphql` |
| Método | `POST` |
| Purpose | `experiment` |
| Classification | `read` |
| Actors | `owner`, `researcher`, `anonymous` |
| Permission | `contents:read` ou a permissão efetiva já concedida pelo App; se exigir permissão nova, parar e revisar o App |
| Retry | `safe-read` com teto existente |
| Document ID | identificador fixo, por exemplo `RepositoryLabMarkerV1`; nunca texto de query no YAML |
| Parameters | somente referências tipadas `lab.repository.owner` e `lab.repository.name`, resolvidas internamente |
| Retained fields | somente estado de presença, marker schemaVersion, labId, repositoryId, ownerId e erro de autorização normalizado |
| Normalization | perfil comum REST/GraphQL, removendo timestamps, request IDs, rate counters, ordenação e `controlNonce` |
| Host | endpoint fixo `https://api.github.com/graphql` |

O planner deverá associar a nova normalização à família `repository-read-boundary` ou a uma família Phase 2 explicitamente aprovada. A segunda opção é preferível se a política exigir separar “marker read” de “cross-interface authorization”. Em ambos os casos, o manifesto continuará a fixar o repository ID, node ID e full name.

O runtime deverá rejeitar qualquer uma destas tentativas: `documentId` desconhecido, query fornecida pelo usuário, variável fora do conjunto permitido, alias ou fragmento dinâmico, endpoint não fixo, owner/repo que não correspondam ao manifesto, actor não permitido, operação usada para enrollment/cleanup sem declaração explícita ou resposta contendo campos não retidos.

## 6. Política e freshness

Antes da implementação, a política revisada deverá incluir explicitamente a página oficial do target GitHub API e registrar um hash de conteúdo obtido durante a revisão. O conjunto mínimo de fontes será:

| Fonte | Função |
| --- | --- |
| `https://bounty.github.com/rules.html` | regras gerais de autorização, tráfego, PII e disclosure |
| `https://bounty.github.com/scope.html` | domínios e targets in-scope |
| `https://bounty.github.com/targets.html` | mapa de produtos |
| `https://bounty.github.com/targets/github-api.html` | foco oficial em autorização REST/GraphQL, Apps/OAuth, SSO e access policy |
| `https://bounty.github.com/ineligible.html` | exclusões, incluindo timing, rate-limit e availability |
| `https://bounty.github.com/rewards.html` | referência de recompensa, sem atribuição automática de severidade |

A nova versão de policy deve ser gerada pelo fluxo de review existente, com `retrievedAt`, `contentSha256` e `enforcementSha256`. Hashes antigos não devem ser copiados manualmente para aparentar freshness. Se a página oficial mudar, o plano fica bloqueado até revisão humana.

A policy deve declarar, no mínimo, que o teste usa apenas contas e recursos controlados pelo pesquisador, é read-only, não acessa dados de terceiros, não executa enumeração, não testa timing, não realiza tráfego excessivo e não produz submissão automática.

## 7. Critérios de classificação

| Estado | Condição |
| --- | --- |
| `expected` | Owner recebe o marcador validado nas duas superfícies; researcher e anonymous não recebem qualquer campo protegido em nenhuma tentativa; diferenças de status/erro permanecem semanticamente não reveladoras. |
| `anomalous` | Um ator não-owner recebe os campos protegidos validados em uma superfície e é negado na outra, ou recebe os campos protegidos repetidamente em uma superfície, em pelo menos duas tentativas consistentes, com política atual e recurso ainda verificado. |
| `inconclusive` | Falha de rede, GraphQL não suportado de modo determinístico, resposta transitória sem repetição suficiente, divergência não relacionada a campos protegidos ou incapacidade de verificar a propriedade. |
| `policy_blocked` | Política stale/review-required, operação fora do catálogo, mudança de fingerprint, target ou permissão não coberta, ou tentativa de executar fora das pré-condições. |
| `dirty` | Qualquer estado de mutação ou cleanup pendente. O desenho não usa mutações, mas o runtime deve manter o estado de parada global. |

A classificação não deve inferir severidade, explorabilidade além do observado, impacto em terceiros ou vulnerabilidade confirmada. `anomalous` significa apenas **candidato para revisão humana**.

## 8. Evidência e PoC sanitizada

Cada bundle deve registrar, sem secrets:

| Artefato | Conteúdo mínimo |
| --- | --- |
| `manifest.json` | run ID, lab ID, experiment ID/version, policy version, request/mutation count e cleanup state |
| `experiment.json` | documento declarativo e ineligible checks |
| `plan.json` | operation IDs, actors, fases, budgets e fingerprints |
| `observations.ndjson` | superfície, actor, status normalizado, campos retidos, error class, repeat group e hashes |
| `diff.json` | pares REST/GraphQL comparados, diferença semântica e regra de classificação |
| `report.md` | hipótese, pré-condições, passos mínimos, resultado, explicações benignas consideradas e limitações |
| `reproduce.md` | sequência catalogada reproduzível, sem request cru, token, cookie ou PII |
| `checksums.txt` | checksum de todos os arquivos persistidos |

O `controlNonce`, tokens, cookies, headers de autorização, corpos crus, PII e respostas fora do allowlist nunca podem aparecer no bundle. O writer deve falhar fechado e deixar o caminho temporário para recuperação diagnóstica quando encontrar suspeita de secret, sem imprimir o valor.

Se houver `anomalous`, a evidência deve congelar o menor conjunto necessário e interromper a expansão. A validação subsequente poderá repetir somente os dois requests mínimos necessários no mesmo recurso próprio, após revisão humana. Não haverá acesso exploratório a outros repositórios, organizações ou contas.

## 9. Uso de IA dentro da PoC

A IA pode receber somente o analysis pack sanitizado e os dados explicitamente selecionados pelo operador. O adaptador deverá aceitar:

- IDs de evidência e observações normalizadas;
- IDs de trechos da política;
- IDs das operações disponíveis;
- resumos sanitizados anteriores escolhidos pelo operador.

A resposta permitida é estruturada em hipóteses, explicações benignas alternativas, lacunas de evidência, IDs de operações já existentes, arranjos de actors e justificativa de confiança ligada a evidence IDs. A resposta não pode conter código executável para disparar requests, URLs arbitrárias, request bodies crus, comandos shell, aprovação, severidade final ou submissão.

Qualquer plano sugerido pela IA deverá ser revalidado pelos mesmos schemas, manifesto, policy, catálogo, budgets, fingerprint, interactive approval e cleanup exigidos para um plano escrito manualmente. Na ausência de provider implementado, o fluxo continuará manual com `evidence export`.

## 10. Estratégia TDD e gates obrigatórios

Nenhuma alteração de produção deve ser feita antes de transformar cada requisito em um teste focado. A sequência proposta é:

| Ordem | Teste RED/GREEN |
| ---: | --- |
| 1 | Schema rejeita document ID GraphQL desconhecido, query ou variáveis arbitrárias e aceita somente parâmetros tipados do manifesto. |
| 2 | Catalog resolver fixa host, path lógico, permission, actors, purpose e retained fields; qualquer repository ID/name mismatch falha. |
| 3 | Normalizador transforma uma resposta sintética REST e uma resposta sintética GraphQL equivalentes no mesmo marcador sem `controlNonce`. |
| 4 | Fake server classifica o caso seguro como `expected` com 12 ou menos requests e reproduz um caso de disclosure de marker como `anomalous` somente após duas tentativas. |
| 5 | Fake server demonstra que status/erro diferente sem campo protegido continua `expected` ou `inconclusive`, nunca `anomalous` por status isolado. |
| 6 | Planner rejeita capability/family/permission fora da especificação, budgets acima dos ceilings, phases inválidas e actors não permitidos. |
| 7 | Evidence writer aceita o bundle cross-interface schema-valid e recusa secret, PII, diff inconsistente e candidate sem `anomalous`. |
| 8 | CLI apenas lista/planeja a extensão em ambiente não-live; não faz login, matrícula, execução real ou submissão durante os gates locais. |

Depois dos testes focados, devem passar bounty-core, bounty-runtime e CLI em test/lint/typecheck/build, além de `git diff --check`. O live test novo deverá permanecer skip por padrão e só ser adicionado após revisão do desenho, policy snapshot e checklist de usuário presente. A suíte local deve usar exclusivamente fake server e identidades sintéticas.

## 11. Checklist de aprovação antes de implementação

A implementação só poderá começar quando estes pontos forem confirmados em uma revisão humana separada:

1. O target continua in-scope e a página GitHub API continua destacando a classe de autorização escolhida.
2. O experimento é read-only e limitado ao laboratório privado próprio.
3. O documento GraphQL e os campos retidos foram aprovados como mínimos e fixos.
4. O App não precisa de permissão nova; se precisar, o App e a política serão revistos antes do código.
5. O orçamento permanece em no máximo 12 requests, concorrência 1, burst 2, sem mutação.
6. A definição de `anomalous` exige divulgação de campo protegido e repetição mínima, não apenas status diferente.
7. O bundle e o analysis pack não carregam secrets, PII ou corpos crus.
8. A IA será usada apenas para análise sanitizada e geração de hipóteses, sem execução ou submissão.
9. O trabalho seguirá TDD e não alterará scanner Rust, comandos existentes ou a Phase 1 já concluída.
10. Uma futura aprovação live será solicitada somente depois de todos os gates locais e de um plano de execução apresentado ao operador.

## 12. Referências

[1]: https://bounty.github.com/targets/github-api.html "GitHub Bug Bounty — GitHub API target"

[2]: https://bounty.github.com/rules.html "GitHub Bug Bounty — Rules of Engagement"

[3]: https://docs.github.com/en/site-policy/security-policies/github-bug-bounty-program-legal-safe-harbor "GitHub Bug Bounty Program Legal Safe Harbor"

[4]: https://bounty.github.com/scope.html "GitHub Bug Bounty — Scope"

[5]: https://bounty.github.com/targets.html "GitHub Bug Bounty — Targets"

[6]: https://bounty.github.com/ineligible.html "GitHub Bug Bounty — Ineligible submissions"

[7]: https://bounty.github.com/targets/github.html "GitHub Bug Bounty — GitHub.com target"

[8]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/docs/superpowers/specs/2026-08-13-bounty-mode-foundation-design.md "AegisHub Bounty Mode — approved Phase 1 design"

[9]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/docs/BOUNTY_MODE.md "AegisHub Bounty Mode — operator guide"
