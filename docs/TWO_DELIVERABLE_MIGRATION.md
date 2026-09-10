# Contrat de migration vers deux livrables

## Portée

Ce document fige la frontière de confiance pendant la migration. Depuis le
sprint 12, les crates sont `aaph-authority` et `aaph-pep`; les wrappers de
processus historiques restent compatibles et aucune route ne change. Le PoC
reste `NON_PRODUCTION_DEMO`.

## État actuel

Deux processus sont livrés : l'agent Python et `aaph-server`. Authority/PDP et
PEP restent des modules séparés dans le serveur. Le PEP est seul monté
sur `demo/workspace/inbox` et `demo-data/output`. Les bases SQLite Authority et
PEP sont distinctes. L'administration appartient à Authority et n'est pas
présente dans l'image agent.

Routes Authority : `/health`, `/v1/sessions`, `/v1/actions/propose`,
`/v1/instances/:instance_id`, `/v1/decisions/:request_id`,
`/v1/audit/verify`, `/v1/audit/export`, `/metrics` et la récupération
administrative. Routes PEP : `/health`, `/v1/effects/execute` et
`/internal/v1/containment-events`.

## État cible

Deux livrables seulement : un exécutable local `aaph-agent` et un binaire
distant `aaph-server`. Le serveur conserve deux modules logiques distincts :
Authority/PDP décide et signe ; PEP vérifie indépendamment et exécute. Seul le
module PEP reçoit une capability vers le workspace. La fusion de processus ne
doit jamais devenir une fusion d'autorité ou une fonction d'exécution directe
appelable par Authority.

## Matrice de possession

| Actif | Agent local | Authority/PDP serveur | PEP serveur | Hors livrables |
|---|---:|---:|---:|---:|
| Clé privée agent | oui | non | non | sauvegarde opérateur éventuelle |
| Clé publique agent | dérivable | oui | empreinte dans permit | provisioning |
| Clé privée autorité | non | oui | non | gestionnaire de clés cible |
| Clé publique autorité | non requise | dérivable | oui | provisioning |
| Certificat/chaîne TLS serveur | CA seulement | certificat serveur | certificat serveur | CA hors artefact serveur |
| Secret administratif | non | oui | non | opérateur |
| SQLite Authority | non | oui | non | sauvegarde serveur |
| SQLite PEP | non | non | oui | sauvegarde serveur |
| Workspace | non | non | oui | stockage distant |
| Mandat, manifeste, politique | non | oui | seulement engagements du permit | provisioning |
| Tâche | oui | propositions bornées seulement | requête canonique liée | non |

## Invariants de déploiement

1. Aucun fichier ou montage du workspace n'est accessible à l'agent.
2. Aucune clé privée agent n'est accessible au serveur.
3. Aucune clé d'autorité ni donnée administrative n'est accessible à l'agent.
4. Tout effet distant exige un permit signé puis revérifié par le PEP.
5. Authority et PEP restent des modules distincts, y compris dans un processus.
6. La compromission du planificateur ne crée, restaure ou prolonge aucune autorité.
7. Les interfaces internes futures doivent être typées et fermées ; aucun appel
   direct au système de fichiers ne traverse la frontière Authority–PEP.

## Contrôles reproductibles

La configuration rendue est contrôlée sans modification :

```powershell
docker compose config --format json | python3 demo/check_delivery_boundary.py
```

Un artefact déjà assemblé est inspecté avant publication :

```text
python3 demo/check_delivery_package.py path/to/staged-artifact
```

Le contrôle refuse `.git`, `.venv`, `target`, les sorties, bases, clés privées
et `ca.crt`. Il ne supprime jamais les entrées trouvées.

## Critères de migration

La migration future devra conserver les routes externes jusqu'à une version
explicitement annoncée, prouver les mêmes refus black-box, et montrer par
inspection d'artefact que chaque livrable ne contient que ses possessions.
