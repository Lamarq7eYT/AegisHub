# AegisHub Bounty Mode

## Finalidade e limites

**Bounty Mode é uma bancada de pesquisa de segurança com restrições**, não um caçador autônomo de recompensas. A Phase 1 foi desenhada para comparar, em baixo volume, o comportamento de duas identidades autenticadas somente contra um recurso privado diretamente pertencente ao operador. O sistema planeja operações de um catálogo congelado, exige uma manifestação de laboratório verificado, revalida a política antes da execução, registra mutações antes de enviá-las e produz evidências sanitizadas para revisão humana.

O modo não enumera alvos de terceiros, não aceita URLs arbitrárias em YAML, não realiza exploração genérica, não avalia severidade automaticamente e não envia relatórios, issues ou submissões. Um resultado **candidate** significa apenas que uma diferença reproduzível atravessou a fronteira declarada e merece validação humana; **candidate ≠ vulnerability**. A autorização do operador, o escopo oficial do programa e a análise humana continuam sendo necessários.

> Pesquisas de autorização devem usar contas, repositórios e dados próprios. As regras oficiais do GitHub também exigem limitar dados retornados, evitar PII e interromper a atividade quando houver risco de impacto em terceiros [1].

## Fronteira ética e de autorização

Use Bounty Mode somente em um repositório privado diretamente pertencente ao mesmo proprietário da conta owner. A conta researcher deve ser uma segunda identidade controlada pelo operador, com ID imutável diferente. A manifestação local fixa os IDs numéricos, node IDs, nomes, marcador de controle e hash do marcador; renomear o repositório pode ser verificado, mas reutilização do nome com outro ID bloqueia a execução até nova verificação.

A ferramenta não deve ser usada para testar organizações, repositórios, dados ou contas que o operador não controla. PII, segredos e respostas volumosas são tratados como condições de parada ou conteúdo sanitizado; não tente ampliar a consulta para confirmar impacto. Para um candidato que afete um produto do GitHub, siga o programa oficial e seu canal privado, nunca uma issue pública [2]. Para um problema no próprio AegisHub, use a política privada do repositório em [docs/SECURITY.md](./SECURITY.md) e a política canônica [SECURITY.md](../SECURITY.md).

## Configuração exata do GitHub App

Crie um GitHub App dedicado ao laboratório e habilite **Device Flow**. Ative **expiring user-to-server access tokens**. Não habilite webhooks para esta bancada. Restrinja a instalação ao repositório privado diretamente pertencente à conta owner. Mantenha somente leitura de metadados e `Contents: read/write`; a escrita existe para a matrícula e limpeza do marcador, enquanto o experimento bundled de boundary é read-only e possui `maxMutations: 0`. Não conceda permissões de organização nem permissões adicionais de conta.

O client ID é metadado público da aplicação e não é um segredo. O código nunca deve receber client secret, senha, cookie, código 2FA, access token ou refresh token por chat, fixture, issue ou arquivo de documentação. Tokens de usuário expiráveis são preferíveis porque o GitHub documenta duração curta e rotação por refresh token [3] [4].

A configuração oficial do Device Flow é descrita na documentação do GitHub: o aplicativo apresenta `https://github.com/login/device`, aguarda autorização e faz polling respeitando o intervalo fornecido; `authorization_pending`, `slow_down`, `expired_token` e `access_denied` são estados distintos [3].

## Configuração local

Copie o exemplo não secreto:

```bash
cp .env.example .env
```

No bash, Linux ou WSL2, exporte somente o client ID público:

```bash
export AEGISHUB_GITHUB_APP_CLIENT_ID="SEU_CLIENT_ID_PUBLICO"
export AEGISHUB_BOUNTY_LIVE=0
```

No PowerShell:

```powershell
$env:AEGISHUB_GITHUB_APP_CLIENT_ID="SEU_CLIENT_ID_PUBLICO"
$env:AEGISHUB_BOUNTY_LIVE="0"
```

No Windows Command Prompt:

```text
set AEGISHUB_GITHUB_APP_CLIENT_ID=SEU_CLIENT_ID_PUBLICO
set AEGISHUB_BOUNTY_LIVE=0
```

No Docker, passe o client ID como metadado de ambiente e mantenha o modo live desligado; não monte um arquivo de tokens no container:

```bash
docker run --rm \
  -e AEGISHUB_GITHUB_APP_CLIENT_ID="SEU_CLIENT_ID_PUBLICO" \
  -e AEGISHUB_BOUNTY_LIVE=0 \
  aegishub:local bounty --help
```

## Autenticação e armazenamento

O login usa dois Device Flows separados, um por ator. A CLI verifica imediatamente o usuário autenticado por `GET /user` e compara o ID imutável. O padrão é **session-only**: a credencial fica somente no processo atual e desaparece ao terminar. `--persist` é uma escolha explícita que usa o keyring nativo; não existe fallback para arquivo plaintext.

```bash
node packages/cli/dist/index.js bounty auth login --actor owner
node packages/cli/dist/index.js bounty auth login --actor researcher
node packages/cli/dist/index.js bounty auth status
node packages/cli/dist/index.js bounty auth logout --actor researcher
node packages/cli/dist/index.js bounty auth revoke-local
```

`auth revoke-local` apaga os registros locais. A revogação no GitHub deve ser confirmada pelo operador na página oficial de aplicações: <https://github.com/settings/applications>. A CLI nunca imprime credenciais nem as coloca em relatórios.

## Matrícula e verificação do laboratório

A matrícula deve ocorrer no repositório privado diretamente owner-owned. O comando mostra a alteração do marcador, exige terminal interativo, registra a mutação no journal write-ahead, lê o marcador de volta e só então grava a manifestação local.

```bash
node packages/cli/dist/index.js bounty lab init owner-fixture/lab-fixture
node packages/cli/dist/index.js bounty lab verify
node packages/cli/dist/index.js bounty lab status
```

A verificação bloqueia identidade igual, marcador incompatível, repository ID divergente, política stale, lease ativo, journal sujo e qualquer recurso fora da manifestação. Um ponteiro de execução antigo só pode ser recuperado quando o PID está definitivamente ausente e o journal prova que não há mutação pendente; caso contrário, o bloqueio permanece.

## Planejamento e execução

O experimento conhecido é carregado somente pelo ID fixo `repo.private.contents-read-boundary.v1`. O YAML é limitado a 64 KiB, validado por schema fechado e só pode usar referências tipadas à manifestação do laboratório. O planner resolve essas referências, valida a política, a manifestação, o catálogo, os atores, a ordem de fases, os repeats e os inversos de cleanup, e congela um fingerprint.

```bash
node packages/cli/dist/index.js bounty policy status
node packages/cli/dist/index.js bounty experiment list
node packages/cli/dist/index.js bounty experiment plan repo.private.contents-read-boundary.v1
node packages/cli/dist/index.js bounty experiment run repo.private.contents-read-boundary.v1
```

A Phase 1 mantém os seguintes limites imutáveis:

| Limite | Valor | Consequência |
| --- | ---: | --- |
| Concorrência | 1 | Nunca há operações simultâneas no mesmo run. |
| Requests por segundo | 1 | O token bucket impõe baixo volume. |
| Burst | 2 | No máximo duas permissões iniciais antes da espera. |
| Requests máximos | 12 | O run é bloqueado ao atingir o teto. |
| Mutações máximas | 0 no bundled | O experimento de boundary não modifica o alvo. |
| Timeout | 20 s | Resposta lenta interrompe a operação. |
| Retries de leitura | 2 após a tentativa inicial | Falha transitória não gera retry agressivo. |
| Retries de mutação | 0 | Resposta perdida nunca é replayada. |

Toda operação passa pelo catálogo de origem fixa, usa headers mínimos, `redirect: manual`, autenticação tardia e resposta sanitizada. O run para em mudança de política, 401, rate limit, secondary limit, redirect, payload grande, segredo/PII suspeito, ID fora do laboratório, timeout, mutação de resultado desconhecido, stop cooperativo ou qualquer falha de verificação.

Para uma execução mutante autorizada, o terminal exige `RUN <fingerprint-prefix>`. A aprovação é consumida uma vez, imediatamente antes da primeira mutação. Interrupção não inicia trabalho novo e tenta o cleanup aprovado; falha de cleanup marca o laboratório como dirty e bloqueia mutações futuras.

## Inspeção, evidência e recuperação

Depois de uma execução, inspecione somente um bundle que passe os schemas e os checksums:

```bash
node packages/cli/dist/index.js bounty run inspect RUN_ID
node packages/cli/dist/index.js bounty evidence export RUN_ID --output /caminho/para/analysis-pack
node packages/cli/dist/index.js bounty stop
```

O layout canônico fica em `.aegishub/runs/<run-id>/` e inclui `manifest.json`, `policy.json`, `experiment.json`, `plan.json`, `observations.ndjson`, `diff.json`, `candidate.json` quando aplicável, `report.md`, `reproduce.md` e `checksums.txt`. O manifest retém IDs imutáveis, resultado, contagem de requests/mutações e estado de cleanup. As observações retêm apenas método, endpoint do catálogo, parâmetros sanitizados, status, headers permitidos, corpo normalizado, hash, repeat group, flags de protected data/out-of-lab e versão de política/catálogo.

O redactor é aplicado antes da persistência e novamente na exportação. Segredos, tokens, cookies, PII e bodies acima do teto não são persistidos. O exportador cria um `analysis-pack.json` atomicamente, recusa sobrescrita e só publica dados schema-validos. Um candidato contém IDs de evidência e passos de reprodução catalogados, mas não contém severidade, submissão automática ou dados crus.

Para recuperar um estado dirty, resolva a causa no repositório próprio, confirme independentemente o marcador pelo LabVerifier e pela operação catalogada de verificação, e só então remova o dirty-state. Nunca use um force-clean sem dupla evidência.

## Testes e gate live

A suíte normal usa somente o fake GitHub loopback em `127.0.0.1`, nunca uma conta real. Execute os gates não-live assim:

```bash
pnpm --filter @aegishub/bounty-runtime exec vitest run test/integration
pnpm --filter @aegishub/bounty-runtime test
pnpm --filter aegishub exec vitest run test/bounty-command.test.ts test/existing-command-regression.test.ts
```

A validação live é deliberadamente opt-in e exige o operador presente, um App client ID, TTY interativo, manifestação local já existente, política atual, marcador recém-verificado e confirmação tipada do repository ID e do hash do experimento. Ela não matricula um repositório novo, não aceita alvo não inscrito e não deve ser substituída por um alvo de terceiros:

```bash
AEGISHUB_BOUNTY_LIVE=1 pnpm --filter @aegishub/bounty-runtime test:live
```

Sem presença do usuário e sem laboratório próprio recém-verificado, o gate live permanece **pending**. A ausência desse gate não autoriza improvisar credenciais ou testar GitHub real.

## Disclosure responsável

Um resultado `anomalous` é uma indicação para validação humana. Preserve somente o bundle sanitizado necessário, confirme o impacto no recurso próprio e siga o canal oficial do programa aplicável. Para GitHub, consulte [Rules of Engagement](https://bounty.github.com/rules.html), [scope](https://bounty.github.com/scope), [targets](https://bounty.github.com/targets), [ineligible submissions](https://bounty.github.com/ineligible) e [rewards](https://bounty.github.com/rewards). Para o AegisHub, use o contato privado indicado na política do repositório.

> AegisHub nunca submete uma vulnerabilidade, abre issue pública em nome do pesquisador, escolhe severidade ou envia uma mensagem de disclosure automaticamente.

## Referências

[1]: https://bounty.github.com/rules.html "GitHub Bug Bounty Rules of Engagement"
[2]: https://bounty.github.com/ "GitHub Bug Bounty Program"
[3]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app "Generating a user access token for a GitHub App"
[4]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens "Refreshing user access tokens"
[5]: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps "Authorizing OAuth apps and Device Flow"
[6]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/docs/superpowers/specs/2026-08-13-bounty-mode-foundation-design.md "Approved Bounty Mode design specification"
[7]: https://github.com/LlewxamDev/AegisHub/blob/codex/bounty-mode-foundation/docs/superpowers/plans/2026-08-13-bounty-mode-foundation.md "Versioned Bounty Mode implementation plan"
