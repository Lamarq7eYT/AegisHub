# Triagem live — Hipótese 1 REST/GraphQL

**Classificação:** inconclusiva; nenhum candidato de segurança foi encontrado.

**Escopo:** somente o repositório privado do laboratório `LlewxamDev/aegishub-bounty-lab-2026`, as contas controladas `owner` e `researcher`, e observações anonymous. Não houve acesso a repositório, organização ou dado de terceiros. Não houve mutation, escalada, submissão ou vídeo de sessão live.

## Comportamento observado

A primeira hipótese avaliava se a leitura do marcador privado do laboratório apresentava uma inconsistência de autorização entre a interface REST de Contents e o endpoint GraphQL fixo. Nas tentativas live, as observações sanitizadas registraram owner com leituras permitidas e researcher/anonymous sem `protectedData`. As leituras GraphQL do actor untrusted foram classificadas como `access_denied`; leituras REST negadas foram classificadas como `not_found`.

Na última tentativa diagnóstica, o runner terminou com `result=inconclusive` e `reason=transport_rate_limited` depois de oito observações. O orçamento e o candidate-stop permaneceram ativos; o runner não produziu candidate e não executou uma cadeia de impacto. O rate-limit é uma condição de transporte e não evidência de autorização bypass.

| Campo | Resultado live sanitizado |
| --- | --- |
| Hipótese | `repo.private.rest-graphql-authorization.v1` |
| Requests observadas antes da parada | `8` |
| Mutations | `0` |
| Candidate | não produzido |
| Protected data para untrusted | nenhum observado |
| Classes observadas | `not_found`, `access_denied` |
| Motivo final | `transport_rate_limited` |
| Run IDs das tentativas | `dabf333a-22ca-4abc-ad0e-cd04d7b3fae9`, `80037c1a-d121-4ff8-b90e-8d7c7c8191e5`, `ce5d80f9-55ee-4b7e-8075-e4f7ffab4ce5` |

## Propriedade de segurança esperada

Somente o owner verificado deve receber o marcador protegido do laboratório por qualquer uma das duas interfaces fixas. Actors untrusted devem receber uma negação equivalente ou uma resposta sem campos protegidos, sem que diferenças cosméticas ou de status sejam consideradas vulnerabilidade.

## Evidência reproduzível

A evidência reproduzível disponível é o registro sanitizado do runner, seus contadores e as classes de erro. Não há bundle live final porque o run foi interrompido pelo guard de rate-limit. A primeira execução também revelou que o writer não serializava corretamente runs forçados como inconclusivos quando não havia `diff`; essa integração foi corrigida localmente para preservar o `Diff` inconclusivo produzido pelo classificador, sem alterar a classificação de segurança.

## Impacto efetivamente demonstrado

Nenhum impacto de confidencialidade, integridade, disponibilidade, cross-tenant ou cross-repository foi demonstrado. Nenhum campo de marcador privado foi entregue a researcher ou anonymous. Portanto, não há candidato de segurança a aguardar revisão humana para esta hipótese.

## Impacto apenas hipotético

Se uma interface tivesse entregado de forma repetida o marcador protegido ao researcher, isso poderia caracterizar uma quebra de confidencialidade no recurso próprio e acionaria `candidate-stop`. Isso não ocorreu nesta pesquisa. Não há base para atribuir severidade, muito menos criticidade.

## Possíveis explicações benignas

A explicação observada é compatível com a combinação de controles de autorização e rate-limit do GitHub: REST negou a leitura como `not_found`, GraphQL negou como `access_denied`, e o guard interrompeu a sequência quando a resposta atingiu a condição de rate-limit. Diferenças entre `403` e `404`, por si só, não demonstram exposição de existência nem de conteúdo; a política atual também trata timing e enumeração como inelegíveis.

## Relação com o escopo atual

A hipótese permaneceu dentro do target `github.com`, usou exclusivamente contas próprias e o laboratório próprio, e observou as regras de tráfego baixo e de não acesso a dados de terceiros. Como não houve impacto real e o resultado foi interrompido por rate-limit, a hipótese deve ser marcada como **inconclusiva e encerrada**, não como finding.

Fontes de escopo consultadas antes do live:

- https://bounty.github.com/rules.html
- https://bounty.github.com/scope.html
- https://bounty.github.com/targets.html
- https://bounty.github.com/ineligible.html
