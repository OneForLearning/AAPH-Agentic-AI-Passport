# Instructions permanentes à imposer à Codex

Ces règles s'appliquent à tous les sprints et doivent être intégrées dans le fichier `AGENTS.md` créé au sprint 0.

## Mission

Construire un PoC AAPH minimal, auditable et reproductible. Un agent Python local propose des actions. Un contrôleur AAPH Rust calcule une autorisation bornée et émet une permission courte. Un PEP Rust distant est la seule frontière pouvant produire un effet sur un workspace confiné.

## Invariants de sécurité

1. Identité n'est pas autorisation.
2. Un manifeste comportemental est une borne déclarative, pas une garantie du comportement interne du modèle.
3. Toute sortie de l'agent est hostile jusqu'à validation de schéma, canonicalisation et décision.
4. Seul un mandat valide peut apporter de l'autorité.
5. L'AgentDefinition, le BehavioralManifest, la politique et le budget peuvent seulement réduire ou refuser cette autorité.
6. L'agent ne possède aucun credential distant permanent.
7. Chaque effet nécessite un ExecutionPermit signé, à audience unique, lié au digest exact de la requête, de courte durée et à usage unique.
8. Aucun chemin vers le workspace protégé ne contourne le PEP.
9. Le PEP revérifie indépendamment la signature, l'audience, le digest, les dates, le nonce, les époques et le périmètre de ressource.
10. Une détection de risque ne peut jamais créer, restaurer, agrandir ou prolonger une autorité.
11. Le confinement incrémente une époque monotone et rend les artefacts portant une époque antérieure inutilisables.
12. La récupération crée une nouvelle session et de nouveaux artefacts ; elle ne réactive rien d'ancien.
13. Le budget consommé persiste entre les sessions.
14. Toute erreur inconnue, état inconnu, champ inconnu ou décision indéterminée entraîne un refus.
15. Aucun shell générique, `eval`, `exec`, commande arbitraire, accès Docker socket ou mode privilégié n'est autorisé.

## Périmètre fonctionnel

Les seules actions distantes enregistrées sont :

- `LIST_DIRECTORY` dans `inbox/` ;
- `READ_FILE` dans `inbox/`, avec limite d'octets ;
- `COMPUTE_SHA256` dans `inbox/` ;
- `WRITE_REPORT` dans `output/`, avec limite d'octets.

Les chemins transmis sur le réseau sont relatifs au workspace. Les chemins absolus, `..`, préfixes ambigus, octets NUL et liens symboliques sortant du workspace sont refusés.

La sortie réseau de l'exécuteur n'est pas une capacité enregistrée. Une proposition contenant une destination externe doit être refusée.

## Qualité de code

- Utiliser des types dédiés et des enums fermés pour les identifiants, états, actions, décisions et codes de motif.
- Éviter `unwrap`, `expect`, `panic!`, indexation non vérifiée et conversions silencieuses dans le code de production.
- Garder les modules cohérents et petits ; découper un fichier lorsqu'il mélange plusieurs responsabilités.
- Interdire les secrets, clés privées, bases de données et certificats générés dans Git.
- Ne jamais journaliser une clé, un token complet ou le contenu d'un fichier protégé.
- Ajouter un test pour chaque correction de bug ou invariant de sécurité.
- Les tests négatifs sont aussi importants que les tests positifs.
- Ne pas masquer les warnings. `cargo clippy --workspace --all-targets --all-features -- -D warnings` doit passer à la fin du projet.
- Ne pas ajouter de fonctionnalité hors sprint.
- Ne pas créer de dépendance à Keycloak, OPA, SoftHSM, Vault, SPIFFE, MCP, A2A, Redis, NATS ou PostgreSQL dans ce PoC.

## Discipline de modification

Au début de chaque sprint :

1. Lire `AGENTS.md`, `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` et `docs/SPRINT_STATUS.md`.
2. Inspecter `git status` et préserver toute modification existante de l'utilisateur.
3. Exécuter les tests du sprint précédent avant toute modification.
4. Présenter un plan court des fichiers à modifier.

À la fin de chaque sprint :

1. Exécuter les commandes de validation demandées.
2. Mettre à jour `docs/SPRINT_STATUS.md` avec les tests réellement passés et les limites connues.
3. Afficher la liste des fichiers créés ou modifiés.
4. Signaler clairement tout test non exécuté ou tout risque résiduel.
5. Proposer un message de commit au format `sprint(N): description`.
6. Ne pas effectuer de commit, push, déploiement ou action externe sans demande explicite.
7. S'arrêter ; ne jamais commencer le sprint suivant.
