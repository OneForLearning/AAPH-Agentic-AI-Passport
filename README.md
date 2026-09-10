# AAPH PoC

Ce dépôt construit un PoC minimal, auditable et reproductible d'autorisation
bornée pour un agent. Un agent Python local propose des actions, un contrôleur
AAPH Rust décide si elles sont autorisées, et un PEP/exécuteur Rust distant est
la seule frontière capable de produire un effet dans un workspace confiné.

> **NON_PRODUCTION_DEMO** — ce projet est une démonstration. Il ne fournit pas
> les garanties, le durcissement, l'exploitation ni la gestion de clés requis
> pour un système de production.

## État actuel

`aaph-server` compose Authority et PEP dans un seul processus Rust. Son listener
public HTTPS expose contrôle et effets sur une même origine ; son listener
administratif est distinct. Authority charge les configurations fermées et
émet les permits, tandis que le module PEP reste seul détenteur de la capacité
workspace et revérifie indépendamment chaque effet.

## Ordre prévu des sprints

Les sprints sont réalisés strictement dans l'ordre de leurs prompts : bootstrap
(sprint 0), contrats et primitives typées, mandat et politique, budgets,
permissions, PEP et confinement, quarantaine/récupération, puis agent Python et
démonstration intégrée (sprint 8). Chaque sprint doit être validé et documenté
avant de commencer le suivant.

## Composants

- `crates/aaph-core` : types et contrats purs, sans réseau ni base de données ;
- `crates/aaph-authority` : bibliothèque composable du contrôleur AAPH ;
- `crates/aaph-pep` : bibliothèque composable du PEP/exécuteur et unique frontière d'effet ;
- `crates/aaph-server` : unique binaire serveur, composition et listeners public/admin ;
- `crates/aaph-e2e` : tests intercomposants uniquement ;
- `agent/aaph_agent/` : agent local Python modulaire, installable comme `aaph-agent`.

Les frontières et hypothèses de sécurité sont détaillées dans `docs/`.

## Clés locales de développement

Le sprint 2 fournit uniquement un générateur de clés de démonstration :

```text
cargo run -p aaph-core --bin aaph-keygen -- local-keys/authority
```

Le dossier `local-keys/` est ignoré par Git. Le générateur refuse d'écraser un fichier existant, sauf avec l'option explicite `--force`. Il ne faut jamais employer ces clés ni Ed25519 seul comme profil cryptographique de production AAPH.

## Stockage local du serveur

`aaph-server` applique automatiquement les migrations SQLx des deux
bibliothèques. `AAPH_AUTHORITY_DATABASE_URL` et `AAPH_PEP_DATABASE_URL`
sélectionnent deux bases SQLite séparées. `AAPH_PUBLIC_LISTEN_ADDR` sélectionne
le listener public.
La clé d'autorité peut être fournie par `AAPH_AUTHORITY_SIGNING_KEY`. La clé
publique de l'agent doit être provisionnée avec `AAPH_AGENT_PUBLIC_KEY_FILE`.
Authority refuse de démarrer si ce fichier publiable est absent ou invalide et
ne charge jamais la clé privée de l'agent.

## PEP distant

`AAPH_PEP_WORKSPACE` désigne la racine capability-based. Le PEP interne reçoit
la clé publique dérivée de la clé de signature Authority. Il ne possède aucune
route de commande générique, aucun shell et aucune sortie réseau.

## Administration locale de démonstration

Le contrôleur exige `AAPH_ADMIN_SECRET`, variable qui n'est jamais transmise à
l'agent. La récupération utilise
`POST /v1/admin/instances/{instance_id}/recovery` avec l'en-tête
`x-aaph-admin-secret`. `AAPH_ADMIN_LISTEN_ADDR` configure le listener HTTPS
administratif distinct, sur `127.0.0.1:3002` par défaut. Les événements
monotones sont transmis au PEP par un trait interne après l'écriture Authority.
Le client administratif one-shot se trouve dans `tools/aaph-admin/recover.py` ;
il n'est pas inclus dans l'image ni dans le contexte de construction de l'agent.

## Scénario légitime de l'agent

Installez le paquet et ses dépendances verrouillées dans un environnement virtuel local :

```text
python3 -m venv .venv
.venv/bin/python -m pip install ./agent
```

Fournissez `AAPH_AGENT_CONFIG=config/agent.json` et
`AAPH_AGENT_SIGNING_KEY=local-keys/agent/signing.key`. Sa clé publique doit être
provisionnée dans `AAPH_AGENT_PUBLIC_KEY_FILE` côté contrôleur. L'agent ne
reçoit jamais la clé d'autorité, un accès SSH ou un chemin vers le workspace du
PEP.

```text
aaph-agent run --task demo/legitimate-task.json --dry-run
aaph-agent run --task demo/legitimate-task.json --planner deterministic
```

Le plan fixe liste `inbox/`, lit et calcule SHA-256 de `inbox/report.txt`, puis
demande l'écriture bornée de `output/summary.txt`. Tout `DENY` ou `QUARANTINE`
arrête immédiatement la séquence.

Trois planificateurs sont disponibles : `deterministic` pour CI,
`adversarial-demo` pour l'injection reproductible et `local-llm` pour un modèle
Ollama-compatible limité à l'hôte local. L'installation reste manuelle :

```text
ollama pull qwen2.5:0.5b
ollama serve
aaph-agent run --task demo/legitimate-task.json --planner local-llm \
  --llm-model qwen2.5:0.5b \
  --llm-endpoint http://127.0.0.1:11434/api/generate
```

Le document est d'abord obtenu par un effet AAPH autorisé. La sortie du modèle
est bornée et validée comme schéma fermé avant de devenir une proposition
signée. Aucun fallback permissif ni retry automatique n'est effectué.

## Démonstration d'injection indirecte

La commande suivante crée des clés, bases et un workspace temporaires, démarre
les deux services, puis utilise le même processus d'agent pour les actions
légitimes, la lecture de la fixture empoisonnée, le confinement et les essais
de rejeu et de contournement :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File demo/run-attack.ps1
```

Le mode `--planner adversarial-demo` active exclusivement le marqueur exact
`AAPH_DEMO_ACTION_JSON:`. Son contenu est décodé comme un schéma JSON fermé ;
il n'est jamais exécuté. Le fichier `demo/workspace/secrets/credentials.txt`
contient seulement `DEMO_SECRET_NOT_REAL`. La trace affichée vient des réponses
réelles ; le script ne contient aucune trace de succès préfabriquée.

## Livraison Docker finale à deux conteneurs (sprint 18)

Le contrôleur décide et signe ; le PEP revérifie et reste l'unique frontière d'effet ; l'agent ne possède que sa clé. TLS rustls protège les flux et la CA de développement est épinglée. Le projet ne vise ni orchestration de production, ni haute disponibilité, ni gestion industrielle des clés. Voir `docs/ARCHITECTURE.md`, `docs/TEST_MATRIX.md` et `docs/SECURITY_LIMITATIONS.md`.

Prérequis exacts : Rust/Cargo 1.84, PowerShell, OpenSSL, curl, Python 3.12 avec `agent/requirements.txt`, et facultativement Docker avec Compose v2.

```powershell
cargo run -p aaph-core --bin aaph-keygen -- local-keys/authority
cargo run -p aaph-core --bin aaph-keygen -- local-keys/agent
powershell -NoProfile -ExecutionPolicy Bypass -File demo/generate-dev-certs.ps1
# Sous WSL/Linux : bash demo/regenerate-dev-certs.sh
New-Item -ItemType Directory -Force demo-data/output | Out-Null
```

`local-keys/`, `dev-certs/` et `demo-data/` sont ignorés. Les services refusent de démarrer sans leurs fichiers TLS ; aucune désactivation de vérification n'est prévue.

Pour démarrer localement, renseigner `AAPH_PUBLIC_TLS_CERT`,
`AAPH_PUBLIC_TLS_KEY`, les variables TLS administratives et les variables de
clés déjà décrites, puis lancer `cargo run -p aaph-server`. Le scénario légitime
utilise `aaph-agent run`. La récupération passe par le listener administratif et
exige ensuite une nouvelle session.

```powershell
docker compose config
docker compose build server agent
docker compose up --abort-on-container-exit --exit-code-from agent
powershell -File demo/audit.ps1 verify
powershell -File demo/audit.ps1 export -Output audit-export.json
curl.exe --cacert dev-certs/ca.crt https://localhost:3000/metrics
cargo run -p aaph-server -- --help
cargo run -p aaph-server -- --version
cargo run -p aaph-server -- healthcheck https://localhost:3000/health dev-certs/ca.crt
```

Compose contient exactement `server` et `agent`. `Dockerfile.server` ne livre
que `aaph-server`; `Dockerfile.agent` installe uniquement le paquet agent. Le
client utilise exclusivement `server_url` pour les deux appels successifs :
proposition puis effet PEP logique sur la même origine. Pour construire un
exécutable natif à la plateforme courante :

```text
python -m pip install -r agent/requirements-build.txt
cd agent
pyinstaller --clean --noconfirm aaph-agent.spec
```

Le résultat `dist/aaph-agent` (ou `.exe` sous Windows) est propre à la
plateforme de build. La spec n'embarque aucune clé, tâche, fixture, récupération
administrative ou certificat privé.

Les conteneurs sont non-root, en lecture seule, sans capabilities ni élévation, avec écritures limitées à SQLite, `output/` et `/tmp`. Aucun socket Docker, mode host, mode privilégié ou montage large n'est utilisé. Les réseaux internes ne sont pas une frontière de production. Les logs JSON portent un identifiant de corrélation généré côté serveur, jamais une clé, un permit complet ou le contenu d'un fichier.

Le contrat préparatoire aux deux livrables et ses contrôles non destructifs
sont décrits dans `docs/TWO_DELIVERABLE_MIGRATION.md`.

## Tests black-box des deux exécutables

La matrice du sprint 19 lance les vrais `aaph-server` et `aaph-agent` sur des
ports TLS et dans un répertoire temporaire propres au test. Elle couvre le
scénario légitime, l'injection, le confinement, le redémarrage persistant, la
récupération opérateur, l'obligation d'une nouvelle session et la chaîne
d'audit :

```text
python3 -m pytest -q tests/black_box/test_two_executables.py
```

Le répertoire temporaire est supprimé uniquement après réussite complète. En
cas d'échec, son chemin est affiché et les logs, bases, certificats et workspace
de test sont conservés pour diagnostic. Le harnais ne touche ni aux volumes
Docker ni aux données utilisateur.

## Profil d'identifiants d'effet

Le profil mono-tenant `NON_PRODUCTION_DEMO` définit
`credential_id := permit_id`, `idempotency_key := request_id` et trois valeurs
indépendantes dans chaque permit : `jti` UUIDv7, nonce CSPRNG 128 bits en
base64url sans padding et `effect_operation_id` UUIDv7. Le PEP journalise
durablement `RECEIVED` puis `STARTED` avant l'effet. Un résultat `COMPLETED` est
retourné idempotemment ; une opération ambiguë après crash exige une résolution
opérateur et n'est jamais relancée automatiquement.

Nettoyage non destructif : `docker compose down`, puis supprimer uniquement `local-keys/`, `dev-certs/` et `demo-data/` après vérification de leur chemin. Ce PoC est `NON_PRODUCTION_DEMO` et Ed25519 seul n'implémente pas la cryptographie hybride attendue par AAPH.

## Livraison native finale

Le sprint 20 produit exactement deux exécutables natifs et des preuves
publiables au moyen d'une allowlist fermée :

```text
python3 demo/package_delivery.py
python3 demo/verify_delivery.py dist
(cd dist && sha256sum -c SHA256SUMS)
```

Le paquet ne contient ni configuration runtime, ni clé, certificat, base,
workspace, export d'audit ou outil de récupération. Ces éléments sont fournis
ou générés uniquement après installation. Le guide autonome est
`docs/TWO_BINARY_DEMO.md`. Le PoC démontre le confinement des effets malgré une
sortie de modèle hostile ; il ne garantit pas que le raisonnement du modèle ne
puisse être influencé.
