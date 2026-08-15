# Pesquisa inicial — GitHub Bug Bounty com AegisHub

**Data da revisão:** 2026-08-15
**Estado:** reconhecimento, threat modeling e desenho preliminar; nenhuma nova operação contra GitHub foi executada nesta tarefa.
**Escopo operacional:** somente contas, repositórios e dados controlados pelo operador; qualquer hipótese nova aguarda aprovação humana e, se necessário, uma especificação de extensão do AegisHub.

## 1. Resumo executivo

A proposta é tecnicamente viável como prova de conceito, desde que o AegisHub continue sendo um instrumento controlado de reprodução e evidência, e não um agente autônomo de exploração. A política oficial atual permite pesquisa técnica em serviços GitHub operados pelo GitHub e em targets publicados, mas exige que o pesquisador use contas próprias para investigar autorização, não impacte outros usuários, não acesse PII de terceiros, não faça DDoS, spam, scraping ou tráfego excessivo, mantenha a divulgação privada e forneça passos escritos de reprodução [1]. O safe harbor não se estende automaticamente a terceiros nem autoriza pesquisa em nome de outras entidades [2].

A conclusão principal é que **a Phase 1 atual não deve ser ampliada por meio de YAML, URLs ou operações improvisadas**. Ela executa apenas um experimento seguro e read-only contra um laboratório privado verificado: `repo.private.contents-read-boundary.v1`. Esse experimento compara owner, researcher e anonymous, produz uma classificação `expected` conhecida e valida a cadeia de autenticação, autorização, normalização, redaction e evidência; a própria especificação diz que ele não é esperado descobrir uma vulnerabilidade [3].

Para a primeira hipótese de pesquisa com valor real, recomendo preparar, mas ainda não executar, uma extensão revisada de **consistência de autorização entre REST e GraphQL para um repositório privado próprio**. Essa hipótese corresponde diretamente ao foco oficial do GitHub API em acesso a recursos privados e bypass de autorização [4], mantém o impacto demonstrável exclusivamente no laboratório do operador e pode ser read-only e de baixo volume. Ela exige Phase 2, porque o catálogo atual não contém as operações REST/GraphQL necessárias para essa comparação.

## 2. Regras e escopo atuais registrados como restrições da sessão

| Área | Restrição aplicada à sessão |
| --- | --- |
| Autorização | Testar somente serviços conhecidos como operados pelo GitHub e targets publicados; para autorização, usar contas próprias [1]. |
| Recursos | Não tocar repositórios, organizações, contas ou dados de terceiros, mesmo que públicos; o safe harbor não autoriza terceiros [1] [2]. |
| Automação | Ferramentas automatizadas são permitidas somente sem tráfego excessivo; DDoS, flooding, spam, scanners de larga escala e scraping estão proibidos [1]. |
| Disponibilidade | Pesquisa de DoS só é elegível sob as condições específicas da política; não será usada como primeira hipótese. |
| PII | Não acessar PII de terceiros intencionalmente; limitar consultas aos próprios dados, interromper imediatamente diante de suspeita e apagar cópias locais/cache [1]. |
| Divulgação | O relatório deve ficar no HackerOne, conter passos escritos claros e não ser divulgado publicamente antes de correção [1]. O AegisHub não fará submissão automática. |
| Escopo de produto | A lista atual inclui `github.com`, `githubassets.com`, `githubusercontent.com`, `githubapp.com`, `githubwebhooks.net`, `github.net`, `npmjs.com`, `npmjs.org`, GitHub CLI, Desktop, Mobile, GHES e GHEC, com exceções publicadas por domínio [5]. |
| Exclusões | Timing que revele existência privada, falta de rate limiting, enumeração de email/username, acesso local, DDoS de rede, dependências upstream e várias categorias de Actions, Codespaces, Copilot, Pages e npm são inelegíveis conforme a página atual [6]. |
| Safe harbor | A proteção é condicionada à boa-fé e à consistência com a política; não vincula terceiros. Quando houver dúvida sobre uma ação fora ou não tratada pela política, deve-se perguntar antes ao programa [2]. |

O target GitHub.com destaca escalada de privilégios, bypass de permissões de repositório, bypass de branch protection, recursos de colaboração, importação, componentes SSH e SSRF com condições específicas [7]. O target GitHub API destaca escalada por Apps/OAuth, acesso a recursos privados sem escopo adequado, team discussions, limitações GraphQL, SAML SSO e OAuth Access Policy [4]. Esses focos são hipóteses orientadoras, não autorização automática para executar qualquer técnica.

## 3. Auditoria do AegisHub atual

A auditoria foi feita contra `docs/BOUNTY_MODE.md`, a especificação aprovada, o catálogo, o planner e o experimento bundled. O runtime atual tem uma fronteira deliberadamente estreita:

| Capacidade | Estado atual | Consequência para a pesquisa |
| --- | --- | --- |
| Identidades | Device Flow separado para owner e researcher, com comparação de IDs imutáveis; anonymous é uma terceira perspectiva sem token. | Permite comparar autorização sem pedir senha, cookie, token, refresh token ou 2FA pelo chat. |
| Laboratório | Manifesto local com repositório privado diretamente owner-owned, IDs imutáveis e marcador de prova de controle. | Permite demonstrar impacto apenas em recurso próprio e bloqueia troca de nome por outro ID. |
| Catálogo | Operações fixas de identidade, `repos.get`, leitura do marcador e PUT/DELETE do marcador para matrícula/cleanup. | Não há endpoint arbitrário, replay cru, operação de colaborador, GraphQL de autorização, Actions, Packages, Apps ou organização. |
| Planner | Somente capability `private-repository` e família `repository-read-boundary`; referências limitadas aos campos tipados do manifesto. | Um novo YAML não pode escapar do repositório fixado nem inventar uma capacidade. |
| Budgets | Concorrência 1, 1 request/s, burst 2, máximo 12 requests no experimento, máximo 0 mutações no bundled, timeout 20 s, retries de leitura limitados e zero retry de mutação. | Adequado para comparação de baixo volume; inadequado para brute force, enumeração, flooding ou testes de disponibilidade. |
| Política | Snapshot revisado `github-bounty-2026-08-13.1`, com freshness check contra rules, scope, targets, ineligible e rewards. | Pesquisa deve parar quando a política estiver stale ou exigir revisão. |
| Análise | Normalização determinística, grupos de repetição, differential analysis e estados `expected`, `anomalous`, `inconclusive`, `policy_blocked` e `dirty`. | `anomalous` é somente candidato para revisão humana; nunca vulnerabilidade confirmada. |
| Evidência | Bundle atomicamente escrito, redacted, schema-validado, checksum-verificado e exportável como analysis pack sanitizado. | A prova de conceito pode conter precondições, sequência, observações e hashes sem dados crus ou secrets. |
| Mutação | Interactive terminal, approval fingerprint, write-ahead journal, verificação e cleanup obrigatório. | Não há mutação silenciosa; uma extensão mutante exigiria aprovação e nova revisão. |
| IA | Phase 1 não possui provider embutido; o analysis pack sanitizado pode ser analisado manualmente por ChatGPT/Codex. | A IA pode sugerir hipóteses, explicações benignas, lacunas e IDs existentes, mas não pode emitir URLs arbitrárias, requests crus, código executável ou aprovação [3]. |

O experimento atual `repo.private.contents-read-boundary.v1` faz dez leituras de baixo volume: duas leituras owner de metadata/marcador, quatro probes researcher/anonymous, duas repetições não confiáveis e duas repetições owner. Sua expectativa é que owner receba `200`, researcher/anonymous recebam `403` ou `404`, nenhum campo protegido seja revelado e o resultado seja `expected` [8]. Ele deve permanecer como baseline de segurança, não ser apresentado como descoberta.

A especificação também exclui explicitamente, nesta fase, scanning arbitrário, terceiros, brute force, shell ou JavaScript fornecido pelo usuário, cadeias autônomas, exfiltração, disponibilidade em produção, Mobile/Desktop/CLI, Enterprise Server, Actions, Packages e transições de privilégio organizacional [9]. REST/GraphQL authorization families ficam para Phase 2; Actions, artifacts, Apps, Packages e organização ficam para Phase 3; provider de IA e memória ficam para Phase 4 [3].

## 4. Threat model e hipóteses priorizadas

A propriedade geral que queremos proteger é: **um ator sem a autorização necessária não deve obter dados privados, executar uma ação privilegiada ou conservar acesso depois de uma mudança de estado, quando o recurso de teste pertence ao operador**. Cada hipótese abaixo é uma pergunta de pesquisa, não uma afirmação de vulnerabilidade.

| Prioridade | Hipótese e propriedade | Indicador de possível defeito | Recursos próprios e risco | Catálogo atual | Próximo passo seguro |
| --- | --- | --- | --- | --- | --- |
| 1 | **Inconsistência REST/GraphQL em repositório privado próprio.** A autorização para metadata e contents deve ser equivalente entre interfaces quando o mesmo actor e recurso são comparados. | Researcher/anonymous obtém campo protegido ou uma mutação/consulta que a outra interface nega, em pelo menos duas repetições semanticamente equivalentes. | Um repositório privado do laboratório, duas contas próprias e anonymous; read-only; baixo volume. | **Não disponível.** A família GraphQL/REST necessária não está no catálogo Phase 1. | Especificar uma extensão Phase 2 com documentos GraphQL fixos, operações catalogadas, campos mínimos e nova revisão de política. Esta é a recomendação principal. |
| 2 | **Revogação e mudança de autorização.** Depois de remover uma autorização própria, o actor removido não deve continuar recebendo conteúdo protegido por uma interface diferente. | O mesmo actor, após uma revogação própria e verificada, continua lendo marker ou metadata protegidos enquanto outra interface nega. | Recurso próprio; envolve mudança de estado e cleanup; risco médio por exigir permissão/colaborador e sincronização de estado. | **Não disponível.** Não há operações de collaborator/team permission nem máquina de estado para revogação. | Design separado com operações mínimas de convite/removal, journal, cleanup e regra de parada; não executar em Phase 1. |
| 3 | **Consistência de identidade/ownership após rename.** Um rename legítimo deve preservar o ID e o acesso do recurso; nome recriado com outro ID não deve herdar a matrícula. | Nome antigo ou novo resolve para recurso errado, ou o marcador/manifesto é aceito quando o repository ID mudou. | Recurso próprio; o segundo caso exige delete/recreate ou outro estado destrutivo; risco médio/alto. | **Parcialmente disponível como defesa.** LabVerifier já verifica rename e bloqueia name reuse, mas não existe experimento catalogado para exercitar toda a transição. | Usar primeiro apenas a máquina de verificação local/fake server; uma execução live exigiria operações revisadas e confirmação explícita. |
| 4 | **Limite de acesso entre repository metadata, contents e protected fields.** Um actor sem contents authorization não deve obter o marker normalizado por um endpoint de metadata nem por resposta parcial. | Campo protegido aparece em uma resposta permitida em outra camada, repetidamente, sem depender de timestamps ou headers irrelevantes. | Laboratório próprio; read-only; risco baixo. | **Parcialmente disponível.** O bundled já cobre metadata/marker REST, mas é baseline conhecido-safe e não compara interfaces adicionais. | Manter como regressão e, após aprovação, estender somente com uma operação catalogada nova; não chamar o baseline de PoC de vulnerabilidade. |
| 5 | **Escopo efetivo de GitHub App.** Uma instalação com permissões mínimas não deve acessar conteúdo ou organização além do repositório selecionado. | App com instalação própria obtém recurso fora do repositório pinado ou uma permissão não concedida. | Exige App próprio adicional ou configuração controlada; read-only ideal, mas envolve instalação e possível organização. | **Não disponível.** Não há operações de instalação/App/org no catálogo; Phase 3. | Criar design Phase 3 e confirmar o escopo do programa antes de qualquer nova instalação ou teste. |
| 6 | **OAuth Access Policy/SAML boundary em organização própria.** Uma app ou token não autorizado não deve atravessar a política da própria organização. | Acesso a dado privado próprio ocorre apesar de política de acesso ou SAML SSO negar a integração. | Pode ser de alto valor, porém exige organização própria, configuração administrativa e credenciais/app state adicionais; risco médio. | **Não disponível.** Sem operações org/OAuth policy/SAML e fora das capacidades atuais. | Somente design revisado com organização integralmente controlada; não usar o laboratório de repositório simples como substituto. |
| 7 | **GraphQL resource-limit semantics sem impacto de disponibilidade.** Limites e autorização devem ser aplicados de forma consistente em consultas próprias de baixo custo. | Uma consulta pequena e repetida obtém dados além da autorização ou contorna limite sem aumentar tráfego ou degradar serviço. | Recurso próprio, mas qualquer exploração de limite pode se aproximar de abuso; risco maior que a hipótese 1. | **Não disponível.** GraphQL catalogado atual serve apenas para identidade. | Não priorizar antes de uma extensão revisada que proíba volume, introspecção arbitrária e consultas custosas. |
| 8 | **SSRF em target oficial específico.** A validação de destino e isolamento deve impedir acesso indevido a recursos internos. | O target permite acesso a dados/serviços não autorizados com impacto concreto e mínimo. | Não é demonstrável exclusivamente em recurso próprio do operador; pode envolver infraestrutura de terceiros e tem risco operacional alto. | **Não disponível e não apropriado como primeiro teste.** O catálogo não aceita URL arbitrária e a regra exige atenção ao target específico. | Não executar. Se houver hipótese concreta, solicitar esclarecimento prévio ao programa e criar especificação independente. |

As hipóteses de Copilot prompt injection sem impacto de segurança, falta de rate limiting, timing que revela existência privada, Pages hosted-content, acesso local, DDoS, enumeração de usuários/emails, exposição de OAuth client ID/secret em clientes oficiais e vulnerabilidades meramente de dependências foram descartadas como primeiras linhas por serem expressamente inelegíveis ou proibidas [1] [6] [7].

## 5. Recomendações para uma prova de conceito assistida por IA

A IA pode ajudar de forma compatível com o escopo, mas a prova precisa ser uma evidência reproduzível, não uma narrativa produzida pelo modelo. O fluxo recomendado é: o AegisHub gera um analysis pack sanitizado; o modelo recebe apenas IDs de evidência, observações normalizadas, excerpt IDs da política, catálogo disponível e resumos anteriores escolhidos pelo operador; o modelo devolve hipóteses, explicações benignas alternativas, lacunas de evidência, IDs existentes e uma justificativa de confiança; o operador revisa; somente então um experimento permitido pode ser desenhado e, se exigir novas capacidades, passa por uma nova especificação.

O modelo não deve receber tokens, cookies, PII, corpos crus de terceiros ou credenciais. Também não deve produzir ou executar requests crus, URLs arbitrárias, JavaScript/shell, aprovação de execução ou submissão. O AegisHub deve rejeitar qualquer plano que não passe pelos mesmos schemas, política, manifesto, catálogo, budgets, aprovação e cleanup [3].

Uma PoC candidata deverá registrar, no mínimo, precondições; propriedade esperada; sequência mínima; actor e operação catalogada; resultado observado; repetições; diferença semântica entre atores; impacto apenas em recurso próprio; versão do experimento; versão e fingerprint da política; IDs de evidência; e ausência de secrets. Se o estado for `anomalous`, a interpretação será **candidato para validação humana**, não vulnerabilidade confirmada. O passo seguinte deverá ser apenas a reprodução mínima necessária, seguida de revisão de escopo e rascunho privado para o HackerOne.

## 6. Recomendação de aprovação

Recomendo aprovar somente o **desenho** da Hipótese 1, não sua execução imediata: uma extensão read-only, de baixo volume, para comparar autorização REST/GraphQL no repositório privado `aegishub-bounty-lab-2026`, usando owner, researcher e anonymous, sem terceiros, sem dados reais de outras pessoas, sem mutações e sem consultas custosas. O desenho deverá definir previamente os campos protegidos, os pares de operações, as respostas esperadas, a normalização, o número máximo de repetições e as condições `expected`, `anomalous`, `inconclusive`, `policy_blocked` e `dirty`.

Essa hipótese tem alto valor informacional porque ataca diretamente a classe de autorização destacada pelo GitHub API, mas conserva baixo risco porque o impacto demonstrável é limitado ao recurso privado do operador. No entanto, **o AegisHub atual não pode executá-la**: a extensão requer uma nova revisão de design, catálogo, política, permissões somente se forem indispensáveis, testes de fake server, evidência e aprovação humana. Até essa revisão, o único experimento live autorizado continua sendo o baseline conhecido-safe da Phase 1.

## 7. Estado desta tarefa

Nenhum teste novo, login, mutation, chamada de pesquisa contra GitHub, criação de App, alteração de repositório, submissão ou disclosure foi realizado nesta tarefa. Foram apenas consultadas as páginas oficiais e auditados artefatos locais do repositório. A próxima ação depende da aprovação humana da hipótese e do escopo da extensão.

## Referências

[1]: https://bounty.github.com/rules.html "GitHub Bug Bounty — Rules of Engagement"

[2]: https://docs.github.com/en/site-policy/security-policies/github-bug-bounty-program-legal-safe-harbor "GitHub Bug Bounty Program Legal Safe Harbor"

[3]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/docs/superpowers/specs/2026-08-13-bounty-mode-foundation-design.md "AegisHub Bounty Mode — approved Phase 1 design"

[4]: https://bounty.github.com/targets/github-api.html "GitHub Bug Bounty — GitHub API target"

[5]: https://bounty.github.com/scope.html "GitHub Bug Bounty — Scope"

[6]: https://bounty.github.com/ineligible.html "GitHub Bug Bounty — Ineligible submissions"

[7]: https://bounty.github.com/targets/github.html "GitHub Bug Bounty — GitHub.com target"

[8]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/packages/bounty-runtime/experiments/repo.private.contents-read-boundary.v1.yaml "AegisHub — bundled private contents boundary experiment"

[9]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/docs/superpowers/specs/2026-08-13-bounty-mode-foundation-design.md "AegisHub Bounty Mode — Phase 1 non-goals and later phases"
