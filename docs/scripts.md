# Os scripts da skill, um por um

Os scripts ficam em `skills/security-scan/scripts/`. Este documento explica o que cada um faz, quando roda, o que lê, o que grava e o que nunca faz.

## Por que existem scripts

A skill é, na maior parte, instrução para o agente. Scripts entram onde o trabalho precisa sair igual toda vez, ou onde um erro custa caro:

- **Segredos.** Um modelo pode deixar escapar um valor que leu. Um filtro determinístico, rodando antes de a saída chegar ao modelo, não.
- **Limite de ação.** Decidir se um comando é de leitura não deveria depender do humor do agente.
- **Estado.** Um arquivo que vários agentes escrevem ao mesmo tempo precisa de um único escritor que valide.
- **Graduação.** Os mesmos fatos têm de dar sempre a mesma prioridade.
- **Busca.** Achar todos os caminhos em um grafo é trabalho de algoritmo, não de memória.

## Convenções

- Python 3.8 ou mais novo, só biblioteca padrão. Testados no 3.9 e no 3.15.
- `--help` mostra a interface.
- Código de saída `0` é sucesso; `1` é recusa ou falha de verificação; `2` é "não implementado".
- Todos gravam apenas dentro da pasta da execução, `.security-scan/runs/<id>/`.
- Nenhum imprime valor de segredo, nem em mensagem de erro.
- Sem `--run`, cada script trabalha na execução corrente, apontada por `.security-scan/current`.

## Estado atual

| Script | Estado |
|---|---|
| `guard.py`, `redact.py`, `blackboard.py` | Implementados e testados |
| `discover_access.py`, `discover_workspace.py` | Implementados e testados |
| `render_report.py` | Relatório de etapa, página do artefato e mapa de arquitetura implementados; `--final` ainda não |
| `grade.py`, `attack_paths.py`, `collectors/*.py` | Esboço: o `--help` descreve a interface planejada e a execução responde `not implemented` |

Quando um script responde `not implemented`, a skill faz o passo à mão, seguindo o arquivo de referência indicado na mensagem, e mantém os mesmos arquivos de saída.

## Quem roda em cada etapa

| Etapa | Scripts |
|---|---|
| 0 | `discover_access.py`, `discover_workspace.py`, `blackboard.py init`, `render_report.py --architecture` |
| 1 a 8 | coletores, `guard.py` antes de cada comando, `redact.py` depois de cada saída, `blackboard.py` para registrar, `grade.py` para cada achado |
| 9 | `attack_paths.py`, `grade.py --all` |
| Fim de cada etapa | `render_report.py --stage N` ou `--live` |
| 10 | `render_report.py --final` |

---

## `guard.py`

**O que faz.** Classifica um comando antes de ele rodar.

**Como.**

1. Recebe o texto de um comando de shell.
2. Corta a linha nos comandos que ela executa: pipelines (`|`), listas (`&&`, `||`, `;`) e redirecionamentos.
3. Classifica cada parte contra as regras de `assets/command-allowlist.yaml`.
4. Responde com a classe da pior parte.

| Classe | Exemplo | Resultado |
|---|---|---|
| `read` | `aws iam list-users` | passa |
| `active` | `curl -I` em endpoint próprio, flag de dry-run | passa só se a execução optou por checagens ativas |
| `collection` | ler o valor de um segredo, baixar um objeto, `cat ~/.aws/credentials` | recusado: é leitura que equivale a coleta |
| `write` | `create`, `put`, `attach`, `deploy`, `git push` | recusado |
| `destructive` | `delete`, `terminate`, `rm` | recusado |
| `unknown` | qualquer coisa sem regra | recusado |

A lista é de permissões, de propósito: comando novo fica bloqueado até alguém olhar e acrescentar uma regra.

Detalhes que fecham atalhos:

- **Verbo antes da regra.** `create`, `delete`, `put` e afins são checados na posição em que cada ferramenta põe o verbo, antes de qualquer regra de leitura.
- **Flag desconhecida antes da operação.** Se aparece uma flag que o script não conhece antes das palavras da regra, o comando vira `unknown`. Assim `aws iam --alguma-flag list-users create-user` não passa por leitura.
- **O que não dá para ver.** Substituição de comando (`$(...)`, crases), subshell, here-document e execução em segundo plano são recusados. O agente roda o comando interno separado.
- **Redirecionamento.** Gravar em arquivo só é aceito dentro de `.security-scan/`.
- **Caminhos protegidos.** Imprimir o conteúdo de arquivos de credencial, `.env`, chaves e estado do Terraform é coleta. Ver metadados (`ls -l`, `stat`) é leitura.

**Entrada.** O texto do comando, a allowlist e o `engagement.yaml` da execução corrente, para saber se checagens ativas foram autorizadas.

**Saída.** A classe e o motivo de cada parte. Código `0` se permitido, `1` se recusado.

**Uso.**

```
guard.py check "aws iam list-users"
guard.py check --allow-active "curl -I https://meu-site.example"
guard.py check --json "kubectl get pods"
guard.py --self-test                 roda a tabela embutida, com mais de 130 comandos
guard.py hook                        lê o JSON de uma chamada de ferramenta, para uso como hook
```

**Sobre o modo hook.** Ele lê a chamada de ferramenta pela entrada padrão. Fora de uma execução em andamento, não interfere. Durante uma execução, recusa com código `2` qualquer comando de shell que não seja leitura. Está implementado e testado com entradas simuladas, mas **não está ligado ao plugin**: falta testá-lo em uma sessão real antes de deixá-lo bloquear comandos.

**Nunca faz.** Não executa o comando que classifica.

**Por que é script.** É a regra mais importante da skill, e regra importante não deve depender de interpretação a cada vez.

---

## `redact.py`

**O que faz.** Tira valores de segredo de qualquer saída, antes de ela ser gravada ou mostrada.

**Como.** É um filtro. Reconhece:

- formatos de chave e token de provedores (nuvem, controle de código, chat, pagamento, IA)
- blocos de chave privada e JWTs
- senhas em URLs de conexão, cabeçalhos de autorização e assinaturas de URL assinada
- valores atribuídos a nomes que parecem segredo (`password`, `token`, `api_key` e parecidos)

Cada valor vira um marcador que guarda o tipo e uma impressão digital:

```
[redacted:<tipo>:<8 primeiros caracteres hexadecimais do SHA-256 do valor>]
```

A impressão digital permite reconhecer o mesmo segredo em dois lugares (a mesma chave no repositório e na pipeline) sem revelá-lo.

Quando a entrada é JSON, o script percorre a estrutura: um valor sob uma chave com nome de segredo é redigido inteiro. Nomes que só descrevem o segredo (`SecretName`, `password_policy`, `AccessKeyId`, `token_type`) ficam como estão. Rodar duas vezes dá o mesmo resultado.

**Entrada.** Texto ou JSON, pela entrada padrão ou de um arquivo.

**Saída.** O texto redigido. Com `--check`, a lista de locais suspeitos (arquivo, linha e tipo, nunca o valor) e código `1` se sobrar algo.

**Uso.**

```
algum-comando | redact.py > evidence/02/x.txt
redact.py --in bruto.json --out evidence/02/x.json
redact.py --check <arquivo-ou-pasta>
redact.py --self-test
```

**Nunca faz.** Não grava o valor original em lugar nenhum, nem em log, nem em mensagem de erro.

**Limite conhecido.** A regra por nome é uma heurística. Ela foi feita para saídas de ferramentas e relatórios; em código-fonte pode acusar ou deixar passar. Os formatos de chave conhecidos não dependem dela.

**Por que é script.** A promessa "nenhum segredo aparece" só vale se for cumprida por algo que não esquece. O `--check` é a última barreira antes de publicar o artefato.

---

## `blackboard.py`

**O que faz.** Cria a execução e é o único que lê e escreve o quadro negro, a memória compartilhada da análise.

**Como.**

- `init` cria a pasta da execução, o `engagement.yaml`, o `blackboard.json` vazio e o `actions.log`. Grava em `.security-scan/current` qual é a execução corrente. Confere se o git ignora `.security-scan/`; se não ignora, acrescenta a linha em `.git/info/exclude`, que é local e não altera nada versionado.
- Cada entrada é validada contra os esquemas em `assets/schemas/`.
- Atribui os identificadores: `N-` para nós, `K-` para fatos, `I-` para intenções, `F-` para achados.
- Recusa um fato `confirmado` sem arquivo de evidência dentro da pasta da execução.
- Recusa texto que contenha valor de segredo, e evidência que ainda não passou pelo `redact.py`.
- Recusa um achado `confirmado` apoiado em fato ainda `a validar`.
- Devolve o identificador existente quando a entrada é repetida.
- Mantém os fatos imutáveis: uma correção cria um fato novo que substitui o antigo (`--supersedes`).
- Usa trava de arquivo, para vários analistas escreverem ao mesmo tempo.

**Entrada.** A pasta da execução e os esquemas.

**Saída.** `blackboard.json`; no `init`, também `engagement.yaml` e a estrutura de pastas. Cada comando que cria algo imprime o identificador criado.

**Uso.**

```
blackboard.py init --scope-kind repository --scope "org/nome" [--include X ...] [--channel artifact] [--language pt-BR]
blackboard.py status
blackboard.py engagement show | set CHAVE VALOR | add CHAVE VALOR
blackboard.py add-node --kind identity --name "papel ci-deploy" --domain aws [--crown-jewel] [--internet-facing]
blackboard.py add-fact --stage 2 --domain aws --statement "..." --evidence evidence/02/x.json [--about N-001]
blackboard.py add-intent --question "..." --from K-012 --for-stage 3
blackboard.py next-intent [--domain aws] [--stage 3]
blackboard.py resolve-intent I-007 --with K-031        (ou --drop "motivo")
blackboard.py link --from N-004 --rel can-read --to N-019 --fact K-031
blackboard.py add-finding --title "..." --stage 2 --facts K-012,K-031 --priority P0 --entry ... --fix "..." --layer 2 ...
blackboard.py coverage --part "organização AWS" --seen partly --note "sem acesso no nível da organização"
blackboard.py stage-note --stage 0 --covered "..." --gap "..." --next "..."
blackboard.py stage-done 0
blackboard.py log --class read --stage 0 --command "aws sts get-caller-identity"
blackboard.py list nodes|facts|intents|relations|findings [--stage N] [--json]
blackboard.py export --format json|architecture
blackboard.py validate
```

Enquanto o `grade.py` não existe, a prioridade do achado é passada à mão em `--priority`, seguindo `references/grading.md`.

**Nunca faz.** Não grava fora da pasta da execução.

**Por que é script.** Sem um escritor único, dois agentes corrompem o arquivo, fatos perdem a evidência e a busca de caminhos deixa de ser confiável.

---

## `discover_access.py`

**O que faz.** Levanta o que a máquina e a sessão alcançam. É a metade "acessos" do mapa da etapa 0.

**Como.**

1. Procura as CLIs instaladas: provedores de nuvem, Kubernetes, controle de código, containers, plataformas.
2. Pergunta a cada uma quem ela é, com o comando de identidade daquela CLI. Só "quem sou eu" e "quais contextos", nunca "o que existe". Cada comando passa pelo `guard.py` antes; o que não for leitura é pulado.
3. Marca cada CLI como alcançável ou não, e sugere os domínios correspondentes.
4. Registra metadados dos arquivos de credencial: caminho, tipo, idade, permissões e se outros usuários da máquina conseguem ler. Não abre o conteúdo.
5. Registra os **nomes** das variáveis de ambiente que parecem credencial. Não os valores.
6. Lê a configuração de SSH: hosts, encaminhamento de agente, salto por bastion. Das chaves, só metadados.
7. Lê a configuração de assistentes de IA, do projeto e do usuário, e registra só nomes: conectores definidos, eventos com hook, quantidade de regras de permissão.
8. Junta a lista de conectores que o agente escreveu em `connectors.json`. Um script não enxerga as ferramentas da sessão; quem lista é o agente.

**Entrada.** O ambiente local. Opcionalmente `connectors.json`.

**Saída.** `access-inventory.json`, e uma linha em `actions.log` para cada chamada de CLI.

**Uso.**

```
discover_access.py --out <run>/access-inventory.json
discover_access.py --identities-only       só as CLIs e quem elas são, para a pergunta de escopo
discover_access.py --no-cli-calls          nenhum comando é executado; só metadados
discover_access.py --only aws,gh,kubectl   limita a algumas ferramentas
discover_access.py --connectors connectors.json
discover_access.py --root <pasta do projeto>
```

**Nunca faz.** Não abre arquivo de credencial. Não faz chamada que liste recursos (isso é dos coletores, depois do escopo). Toda chamada tem tempo limite, e toda saída passa pelo `redact.py`.

**Por que é script.** A lista de CLIs e de arquivos de credencial é a mesma em toda execução, e o cuidado de não abrir os arquivos não pode falhar.

---

## `discover_workspace.py`

**O que faz.** Levanta os sinais de arquitetura que estão no repositório. É a metade "contexto" do mapa da etapa 0.

**Como.** Percorre o diretório de trabalho e reconhece:

- infraestrutura como código: Terraform (provedores, backend, tipos de recurso), CloudFormation, Helm, Kustomize, manifests de Kubernetes
- containers: Dockerfiles (imagens base, se define usuário, portas) e arquivos compose (serviços, portas publicadas)
- CI/CD: sistemas em uso e, dos workflows do GitHub, o que importa para segurança: gatilho `pull_request_target`, permissões declaradas, token OIDC, runner próprio, nomes dos segredos usados e ações de terceiros não fixadas em commit
- manifests de dependência, frameworks e acesso a dados
- arquivos `.env*`: só os nomes das chaves, se há valores preenchidos e se o git rastreia o arquivo
- arquivos que costumam guardar segredo (chaves, estado, credenciais): só o caminho e se o git rastreia
- configuração de assistentes de IA: settings, hooks, conectores, arquivos de instrução, skills
- remotos git, arquivos de dono (CODEOWNERS) e documentação

Com isso classifica a forma do repositório (serviço único, monorepo, infraestrutura, plugin) e sugere os domínios a analisar.

**Entrada.** Os arquivos do repositório. Respeita o `.gitignore`, pula pastas de dependência e de build, e lê no máximo 512 KB de cada arquivo.

**Saída.** `workspace-inventory.json`.

**Uso.**

```
discover_workspace.py --root . --out <run>/workspace-inventory.json
discover_workspace.py --summary            forma curta, para a pergunta de escopo
```

**Nunca faz.** Não executa nenhum arquivo que lê. Não usa rede. Não grava valores de `.env`. Tira credenciais embutidas em URLs de remoto.

**Por que é script.** Varredura de arquivos é rápida e barata em código, e cara e incompleta quando feita pelo agente arquivo por arquivo.

---

## `render_report.py`

**O que faz.** Transforma o quadro negro no que a pessoa lê.

**Como.** Tem quatro modos:

| Modo | O que gera | Quando |
|---|---|---|
| `--stage N` | `stages/NN-<etapa>.md`, o relatório de três partes | fim de cada etapa, em harness sem artefatos |
| `--live` | `live-report.html`, com todas as etapas concluídas, o progresso e a contagem por prioridade | fim de cada etapa, no Claude |
| `--architecture` | `architecture.json` e `architecture.md`, com diagrama | etapa 0 |
| `--final` | o conjunto consolidado | etapa 10; ainda não implementado |

Os relatórios saem no idioma definido em `engagement.yaml`, com os rótulos de `assets/i18n/`. Hoje há inglês e português; outro idioma cai no inglês.

O relatório de etapa mostra os achados da etapa (com prioridade, evidência e visibilidade), os demais fatos, as correções por camada de defesa e o que pode ser explorado, incluindo as perguntas abertas para a etapa seguinte. Na etapa 0 entra também o resumo da arquitetura: quantidade por tipo, joias da coroa e cobertura.

Todo texto vindo dos dados é escapado antes de entrar na página, então um nome de recurso com HTML não quebra o relatório.

Antes de gravar, o script confere o resultado com as regras do `redact.py`. Se sobrar algo com cara de segredo, o arquivo não é gravado.

**Entrada.** `blackboard.json`, `engagement.yaml`, o modelo em `assets/templates/live-report.html` e os rótulos.

**Saída.** Os arquivos acima.

**Uso.**

```
render_report.py --stage 0
render_report.py --live
render_report.py --architecture
```

**Nunca faz.** Não publica nada. Quem publica o artefato é o agente, com a ferramenta de artefatos do harness, sempre no mesmo link.

**Por que é script.** O relatório de cada etapa precisa ter sempre a mesma forma, e a página do artefato precisa ser regerada inteira a cada etapa sem perder as anteriores.

---

## `grade.py` (esboço)

**O que vai fazer.** Aplicar os critérios de P0, P1 e P2 a um achado.

1. Recebe as quatro respostas do achado: entrada, alcance, impacto e visibilidade. Mais o ambiente e o estado da evidência.
2. Aplica os critérios de `references/grading.md`, na ordem P0, P1, P2.
3. Aplica os modificadores: silencioso (sobe um nível), isolado (desce um nível), ponto de estrangulamento (vai primeiro dentro do nível).
4. Devolve a prioridade e a regra que decidiu, por exemplo `P0.4`.

Será determinístico: as mesmas respostas darão sempre a mesma prioridade. O agente poderá sobrescrever, mas só com um motivo por escrito, guardado no achado.

**Nunca vai fazer.** Decidir se o achado é verdadeiro. Isso é do validador.

---

## `attack_paths.py` (esboço)

**O que vai fazer.** Buscar no quadro negro os caminhos de um ponto de entrada até uma joia da coroa.

1. Monta um grafo com as relações do quadro negro.
2. Define os pontos de entrada: ativos expostos à internet, credenciais expostas ou fracas, e duas posições assumidas ("qualquer funcionário de baixo privilégio", "qualquer workload do escopo").
3. Define os alvos: as joias da coroa e o controle administrativo de identidade, nuvem e pipeline.
4. Busca os caminhos. Cada aresta usada tem de se apoiar em um fato.
5. Ordena, marca o passo de evidência mais fraca e dá uma classe de tempo de máquina: minutos, horas ou dias.
6. Conta em quantos caminhos cada achado aparece. Os mais frequentes são os pontos de estrangulamento.

**Nunca vai fazer.** Usar rede ou executar comando. É só cálculo sobre o quadro negro.

---

## `collectors/<domínio>.py` (esboço)

**O que vão fazer.** Um coletor por domínio. Cada um roda a lista fixa de leituras que o playbook daquele domínio precisa para uma etapa: monta o comando, passa pelo `guard.py`, executa com paginação e limite de taxa, passa a saída pelo `redact.py` e grava JSON em `evidence/<etapa>/`.

Em uma sessão só com conectores, o agente faz as mesmas leituras pelo conector e passa os resultados pelo `redact.py`.

`collectors/_template.py` descreve o contrato.

---

## Módulos de apoio

Não são chamados diretamente; os scripts os importam.

| Módulo | Para quê |
|---|---|
| `_yamlite.py` | Lê e escreve o subconjunto de YAML que a skill usa. O Python não traz leitor de YAML, e os scripts não dependem de nada instalado. O que o módulo não suporta dá erro, em vez de ser adivinhado |
| `_schema.py` | Valida dados contra os esquemas JSON da skill, na parte do JSON Schema que eles usam |
| `_common.py` | Onde está a execução corrente, nomes das etapas, carimbo de hora e o registro em `actions.log` |

## Testes

```bash
python3 -m unittest discover -s tests
```

Os testes ficam em `tests/`, na raiz do repositório. Montam em tempo de execução uma pasta HOME e um repositório falsos, cheios de credenciais de mentira, e conferem que nenhum valor chega às saídas. Os segredos falsos são montados por concatenação, para nenhum literal com cara de segredo ficar versionado.
