# Démonstration à deux exécutables

Cette livraison est exclusivement `NON_PRODUCTION_DEMO`. Elle montre que les
effets restent confinés malgré une proposition influencée par une injection ;
elle ne prétend pas empêcher l'influence du raisonnement d'un LLM.

## Installation

Copier les deux fichiers correspondant à la plateforme depuis `dist/` et
vérifier `SHA256SUMS`. Les clés, certificats, configurations, bases et données
de démonstration ne sont volontairement pas livrés. Rust n'est pas requis pour
exécuter le serveur empaqueté ; l'agent PyInstaller contient son runtime Python.

Depuis le dépôt de build, la commande reproductible est :

```text
python3 -m pip install -r agent/requirements-build.txt
python3 demo/package_delivery.py
python3 demo/verify_delivery.py dist
(cd dist && sha256sum -c SHA256SUMS)
```

L'installation de la dépendance de build est une étape opérateur explicite ; le
script de packaging ne télécharge ni outil, ni modèle, ni secret.

## Préparation locale

Depuis le dépôt source, générer après installation les identités et la PKI :

```text
cargo run -p aaph-core --bin aaph-keygen -- local-keys/authority
cargo run -p aaph-core --bin aaph-keygen -- local-keys/agent
bash demo/regenerate-dev-certs.sh
mkdir -p demo-data/inbox demo-data/output
cp demo/workspace/inbox/report.txt demo-data/inbox/
cp demo/workspace/inbox/poisoned-document.txt demo-data/inbox/
```

Fournir séparément `config/agent-manifest.json`, `config/mandate.json` et
`config/policy.json` au serveur, ainsi qu'une configuration agent fermée ne
contenant que `schema_version`, `instance_id` et `server_url`.

## Démarrage du serveur

Configurer les deux bases SQLite, le workspace, la clé Authority, la clé
publique agent, les deux listeners TLS et le secret opérateur dans les variables
`AAPH_*` documentées par le README, puis lancer :

```text
./aaph-server-<plateforme>
```

Le listener public et le listener administratif doivent utiliser des ports
distincts. Le port administratif reste sur loopback et son secret n'est jamais
fourni à l'agent.

## Scénario légitime et attaque

Configurer `AAPH_AGENT_CONFIG`, `AAPH_AGENT_SIGNING_KEY` et
`AAPH_TLS_CA_CERT`, puis exécuter :

```text
./aaph-agent-<plateforme> run --task demo/legitimate-task.json --planner deterministic
./aaph-agent-<plateforme> run --task demo/legitimate-task.json --planner adversarial-demo
```

Le premier scénario réalise les quatre actions enregistrées. Le second lit la
fixture empoisonnée, produit une proposition hors périmètre avec destination
externe, reçoit `QUARANTINE` sans permit et ne lit jamais le faux secret.

## Preuves et récupération

`dist/evidence/` contient les versions, le rapport des validations et la matrice
de conformité, sans état d'exécution ni secret. Les preuves runtime sont
accessibles via `/v1/audit/verify` et `/v1/audit/export`. La récupération est
réservée à l'outil opérateur hors artefact agent :

```text
AAPH_ADMIN_URL=https://localhost:3002 \
AAPH_ADMIN_SECRET=<secret-opérateur> \
AAPH_TLS_CA_CERT=dev-certs/ca.crt \
python3 tools/aaph-admin/recover.py
```

La récupération exige ensuite une nouvelle session ; aucun permit, nonce, JTI
ou budget antérieur n'est restauré.

## Nettoyage non destructif

Arrêter uniquement les processus démarrés pour la démonstration. Avec Compose,
utiliser `docker compose down` sans `-v`. Ne supprimer manuellement que les
dossiers de démonstration dont le chemin exact a été vérifié (`local-keys/`,
`dev-certs/`, `demo-data/`). Ne jamais supprimer une base ou un volume
utilisateur. Les migrations SQLite restent non destructives et compatibles avec
les bases créées par les versions précédentes du PoC.

Authority et PEP sont séparés logiquement mais partagent le processus
`aaph-server` dans cette livraison. Une version de production devrait permettre
leur redéploiement séparé avec une frontière authentifiée adaptée ; les réseaux
Docker du PoC ne constituent pas cette frontière.
