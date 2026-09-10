# État des sprints

## Sprint 0 — bootstrap

État : squelette créé ; validation dynamique indisponible dans l'environnement de réalisation.

### Réalisé

- workspace Cargo resolver 2 avec quatre membres ;
- bibliothèque cœur sans I/O, deux binaires minimaux et crate de tests intercomposants ;
- squelette Python, configurations, fixtures et documentation de sécurité ;
- fichier Compose valide sans service fictif.

### Validations

- `cargo fmt --all -- --check` : non exécuté, `cargo` absent ;
- `cargo check --workspace --all-targets` : non exécuté, `cargo` absent ;
- `cargo test --workspace` : non exécuté, `cargo` absent ;
- `python3 -m py_compile agent/agent.py` : non exécuté, interpréteur inaccessible ;
- JSON : validation syntaxique effectuée avec PowerShell.

### Limites connues

Le sprint 0 ne contient volontairement aucune signature, politique, budget, quarantaine, protection contre le rejeu, sandbox, accès fichier, endpoint ni algorithme d'autorisation. L'édition a été corrigée vers Rust 2021 et `rust-version = 1.84` après découverte de la toolchain installée hors du `PATH`.

## Sprint 1 — modèle de domaine

État : implémenté.

### Réalisé

- neuf newtypes d'identifiants critiques et timestamp UTC explicite ;
- objets de domaine requis, actions/décisions/états/codes de motif fermés ;
- conversion explicite d'une proposition hostile vers une requête canonique ;
- machines à états encapsulées, preuve typée de récupération et époque vérifiée ;
- budget et tailles bornés, objets de frontière stricts avec Serde ;
- tests positifs et négatifs du modèle.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p aaph-core` : réussi, 17 tests unitaires et 0 échec ;
- `cargo check --workspace --all-targets` : réussi ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Aucune politique, persistance, canonicalisation de chemin ou exécution n'est implémentée. `RecoveryValidation` représente seulement une preuve logique fournie par un futur composant. Les chaînes métier hors nom d'action restent à borner dans les sprints qui définiront leurs schémas définitifs.

## Sprint 2 — canonicalisation et artefacts signés

État : implémenté et validé.

### Réalisé

- canonicalisation RFC 8785 via `serde_jcs` et transcripts à longueurs explicites ;
- empreintes SHA-384 et quatre séparations de domaines NUL-terminales ;
- signatures Ed25519 des propositions, permits et événements de confinement ;
- base64url sans padding strict pour clés publiques, signatures et empreintes ;
- liaison complète des champs critiques du permit et contrôle temporel configurable ;
- chargement de clé privée depuis fichier ou environnement sans sérialisation ni journalisation ;
- générateur `aaph-keygen` local, marqué démonstration et sans écrasement implicite ;
- vecteurs déterministes et tests positifs/négatifs réservés aux tests.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p aaph-core` : réussi, 30 tests et 0 échec ;
- `cargo test --workspace` : réussi, 31 tests et 0 échec ;
- `cargo check --workspace --all-targets` : réussi ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Ed25519 seul n'est pas le profil hybride de production AAPH. La protection matérielle, rotation et révocation de clés, la politique, les API, la persistance et l'exécution restent hors de ce sprint. Les versions `zeroize` et `base64ct` sont épinglées pour rester compatibles avec Rust 1.84.

## Sprint 3 — autorité, politique et budget

État : implémenté et validé.

### Réalisé

- validation distincte du mandat et autorité dérivée du mandat uniquement ;
- intersection typée avec définition et manifeste, sans élargissement possible ;
- PDP local fermé pour actions, chemins logiques, finalités, tailles et destinations ;
- verdict déterministe avec refus ordinaire, confinement et erreur fail-closed ;
- attribution prudente des signaux de rejeu, expiration, signature et liaison ;
- registre à trois dimensions respectant `consumed + reserved <= capacity` ;
- transitions disponible, réservée, engagée et libérée avec contrôles d'idempotence ;
- conservation de la consommation et libération des réservations à la fermeture de session.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p aaph-core` : réussi, 43 tests et 0 échec ;
- `cargo test --workspace` : réussi, 44 tests et 0 échec ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Le registre est un modèle en mémoire sans SQLite. Le contrôleur ne résout pas les liens symboliques et n'émet encore aucun permit. Aucun endpoint HTTP ni intégration aux services binaires n'est ajouté dans ce sprint.

## Sprint 4 — SQLite et audit chaîné

État : implémenté et validé.

### Réalisé

- migration SQLx versionnée pour les treize tables du contrôleur ;
- foreign keys par connexion, contraintes `CHECK`/`UNIQUE` et index ciblés ;
- repositories étroits et reconstruction validée des objets de domaine ;
- transactions immédiates pour budgets et audit, décision avec requête atomique ;
- concurrence budgétaire bornée, rollback complet et époque conditionnelle ;
- migrations automatiques au démarrage sans API réseau ;
- audit SHA-384 chaîné avec genesis constant et séparation de domaine ;
- détection de modification, insertion, suppression intermédiaire et permutation.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p authority-service` : réussi, 9 tests et 0 échec ;
- `cargo test --workspace` : réussi, 53 tests et 0 échec ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Le journal est tamper-evident, pas immuable contre root, et aucun ancrage externe de tête de chaîne n'existe encore. Le stockage ne décide jamais de l'autorisation. Le confinement multi-table complet est réservé au sprint suivant ; aucune API HTTP n'est exposée.

## Sprint 5 — API du service d'autorité

État : implémenté et validé.

### Réalisé

- six routes Axum versionnées avec limitation du body avant parsing et réponses fermées ;
- création de session signée, courte, liée aux époques courantes et au budget persistant ;
- pipeline ordonné de résolution, états/dates, signature liée, anti-rejeu, canonicalisation, mandat, atténuation, politique et budget ;
- émission Ed25519 d'un permit court lié au digest exact, avec libération de réservation si la signature échoue ;
- horloge, signataire et dispatcher sans effet injectables ;
- chargement et validation stricte des trois configurations de démonstration ;
- consultation d'instance/décision et vérification du journal d'audit.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p authority-service` : réussi, 13 tests et 0 échec ;
- `cargo test --workspace` : réussi, 57 tests et 0 échec ;
- `cargo check --workspace --all-targets` : réussi ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Le dispatcher est volontairement un faux et aucun effet distant n'est produit avant le sprint 6. Les clés générées en mémoire par défaut ne conviennent qu'à une exécution locale éphémère. Le journal reste tamper-evident sans ancrage externe et le service n'intègre pas TLS ni gestion matérielle des clés.

## Sprint 6 — PEP distant et exécuteur confiné

État : implémenté et validé.

### Réalisé

- routes de santé, exécution et événements internes de confinement ;
- vérification indépendante et fail-closed des permits, digests, détenteurs, époques et nonces ;
- stockage SQLite PEP séparé avec consommation atomique anti-rejeu ;
- workspace capability-based `cap-std`, quatre actions fermées et aucune commande générique ;
- lectures/listes/écritures bornées, écriture temporaire puis renommage atomique ;
- événements de confinement signés et époques strictement monotones ;
- résultats structurés et stockage de leur seul digest.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p remote-pep` : réussi, 6 tests et 0 échec ;
- `cargo test --workspace` : réussi, 63 tests et 0 échec ;
- `cargo check --workspace --all-targets` : réussi ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Le profil cryptographique reste celui de démonstration Ed25519. Le transport
n'intègre pas TLS. Le nettoyage des nonces expirés est volontairement absent :
ils ne peuvent donc pas être réactivés, mais la table croît sans compaction.
Sous Windows, le test de symlink dépend du droit système de créer un lien ; il
a été exécuté avec succès dans l'environnement de validation présent.

## Sprint 7 — quarantaine, propagation et récupération

État : implémenté et validé.

### Réalisé

- confinement transactionnel, incrément unique et fermeture des sessions ;
- libération des réservations sans modification des compteurs consommés ;
- événement signé, propagation HTTP attendue et échec explicitement visible ;
- cache PEP monotone, répétition idempotente et rejet des anciens permits ;
- récupération administrative à secret constant-time et validation nouvelle ;
- aucune restauration d'artefact et nouvelle session obligatoire ;
- mesure locale application PEP–premier rejet sous une seconde.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo test -p authority-service` : réussi, 15 tests et 0 échec ;
- `cargo test -p remote-pep` : réussi, 7 tests et 0 échec ;
- `cargo test --workspace` : réussi, 66 tests et 0 échec ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

La fenêtre distribuée contrôleur–PEP subsiste. La mesure locale ne garantit
aucune latence réseau. Le secret administratif et HTTP sans TLS sont des
simplifications strictement réservées à la démonstration.

## Sprint 8 — agent Python et scénario légitime

État : implémenté ; validations Python indisponibles dans l'environnement.

### Réalisé

- CLI `run --task` et `--dry-run`, configuration et clé chargées par chemins d'environnement ;
- schémas fermés de configuration et de tâche ;
- interface `Planner` et plan déterministe des quatre actions ;
- JCS RFC 8785, transcript big-endian, SHA-384, Ed25519 et base64url compatibles Rust ;
- arrêt fail-closed sur refus et aucun accès direct au workspace distant ;
- tests Python du plan, des schémas, de la configuration, du refus et du scénario HTTP ;
- fixture croisée dont la signature Python-compatible est vérifiée par Rust ;
- versions Python verrouillées dans `agent/requirements.txt`.

### Validations

- `python3 -m py_compile agent/agent.py` : non exécuté, aucun interpréteur Python accessible ;
- `python3 -m pytest agent/tests` : non exécuté, aucun interpréteur Python accessible ;
- `cargo test --workspace` : réussi, 67 tests et 0 échec ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

L'environnement de réalisation ne fournit ni `python`, ni `python3`, ni le
lanceur `py`; la création du venv et les six tests Python restent donc à
exécuter sur une machine disposant de Python. Aucun service réel n'a été lancé
pour la démonstration intégrée ; le scénario client utilise des transports HTTP
de test déterministes.

## Sprint 9 — injection indirecte et démonstration E2E

État : implémenté ; validations Rust réussies, validation Python bloquée faute d'interpréteur.

### Réalisé

- workspace de démonstration avec document empoisonné et faux secret hors scope ;
- planificateur vulnérable opt-in à marqueur unique et schéma fermé ;
- même instance et même session pour actions légitimes, attaque et nouvelle tentative ;
- contrôles explicites de quarantaine sans permit, époque, rejeu, accès PEP direct et audit ;
- résumé construit uniquement à partir des réponses observées ;
- deux scénarios Rust dans `aaph-e2e` pour confinement/audit et budget/récupération ;
- script processus avec clés, bases et workspace temporaires.

### Validations

- `cargo fmt --all -- --check` : réussi après application du formatage ;
- `cargo test --workspace` : réussi, 68 tests et 0 échec ;
- `cargo check --workspace --all-targets` : réussi ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `cargo test -p aaph-e2e --test quarantine_e2e -- --nocapture` : réussi, 2 tests et trace calculée observée ;
- analyse syntaxique de `demo/run-attack.ps1` : réussie ;
- `python3 -m pytest agent/tests` : tenté, échec avant collecte car aucun interpréteur Python n'est accessible ;
- démonstration `powershell -NoProfile -ExecutionPolicy Bypass -File demo/run-attack.ps1` : tentée ; clés temporaires et services Rust lancés, puis échec explicite au démarrage de `python3`.

### Limites connues

Les tests du client Python utilisent un transport HTTP déterministe. Le test
Rust E2E calcule effectivement politique, confinement, audit et invariants de
budget, mais la preuve processus complète ne pourra être obtenue qu'en lançant
le script documenté sur une machine équipée de Python et des dépendances
verrouillées. Le script nettoie son environnement temporaire même après cet
échec. Aucune trace processus n'est fabriquée dans ce dépôt.

## Sprint 10 — durcissement et livraison

État : implémenté ; validations Rust réussies, validations Python/Docker/certificats bloquées par les outils absents.

### Réalisé

- TLS rustls obligatoire sur contrôleur et PEP, client contrôleur–PEP à CA épinglée et validation CA côté agent ;
- script OpenSSL de CA/certificat de développement, dossiers sensibles ignorés ;
- images multi-stage non-root et Compose en lecture seule, sans capabilities, privilèges, host network ni Docker socket, avec volumes et réseaux explicites ;
- logs JSON `tracing`, corrélations générées côté serveur, décisions/transitions/ReasonCodes sans contenu ni artefact complet ;
- métriques de décisions, rejeux et dernière propagation, export et vérification du journal ;
- correction de la collision des noms de bases SQLite de tests inter-processus ;
- revue finale, limites de sécurité et matrice exigences–tests.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 68 tests et 0 échec ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `cargo test -p aaph-e2e --test quarantine_e2e -- --nocapture` : réussi, 2 tests et trace réelle calculée ;
- `python3 -m pytest agent/tests` : tenté, impossible avant collecte car `python3.exe` est inaccessible ;
- `docker compose config`, construction et démonstration : tentés mais non exécutables, commande `docker` absente ;
- génération des certificats : tentée mais non exécutable, commande `openssl` absente ; aucun certificat partiel conservé ;
- `cargo-audit` et `cargo-deny` : non exécutés car non installés.

### Limites connues

La démonstration TLS et conteneurisée n'a pas produit de trace sur cette machine. La présence de Git ne peut pas être inspectée, donc l'absence de secret suivi est déduite de `.gitignore` et de la recherche du workspace, pas prouvée par l'index. Les limites architecturales sont détaillées dans `docs/SECURITY_LIMITATIONS.md`.

### Revalidation Docker et PKI de développement (2026-09-05)

- CA régénérée avec `CA:TRUE,pathlen:0`, usages `keyCertSign` et `cRLSign`, SKI et AKI ;
- certificats distincts pour `authority-service` et `remote-pep`, avec `CA:FALSE`, `serverAuth` et SAN dédiés ;
- `openssl verify` réussi pour les deux certificats serveur ;
- `docker compose config`, arrêt sans suppression des volumes, régénération, recréation et healthchecks : réussis ;
- scénario légitime : agent `Exited (0)`, quatre effets autorisés et exécutés ;
- démonstration de quarantaine : destination externe refusée, confinement à l'époque 2, nouvelle action et ancien permit refusés, audit valide ;
- correction de régression : `LIST_DIRECTORY inbox/` est reconnu comme la racine logique autorisée, avec test dédié.

### Correctif d'identifiants persistants (2026-09-05)

- suppression du compteur de production réinitialisé au redémarrage ;
- réservations et permits générés en UUIDv7, nonces générés par CSPRNG ;
- validation Docker sur les volumes SQLite existants : agent `Exited (0)` après
  redémarrage, sans collision ni réponse 500 ; services healthy ;
- `cargo test --workspace --all-features` : réussi, 78 tests ;
- `python3 -m pytest agent/tests` : réussi, 10 tests ;
- `docker compose config` et reconstruction des trois images : réussis ;
- revalidation sur les volumes persistants : services healthy, quatre effets
  exécutés et agent `Exited (0)` sans collision ni réponse 500 ;
- les primitives complètes `jti`, `idempotency_key` et `effect_operation_id`
  du draft ne font pas partie des objets fermés actuels du PoC et restent un
  écart explicitement documenté, sans ajout de champ non reconnu.

## Sprint 11 — contrat de migration et frontière de confiance

État : implémenté et validé, sans renommage ni fusion de service.

### Réalisé

- contrat actuel/cible et matrice de possession pour deux livrables ;
- invariants de déploiement et futures preuves black-box ;
- retrait de la clé privée agent du service Authority : seule sa clé publique
  est maintenant provisionnée côté serveur ;
- diagnostic non destructif de partage de clé privée agent ;
- contrôle non destructif des contenus interdits dans un artefact préparé ;
- tests positifs et négatifs des deux diagnostics.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 78 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `python3 -m pytest -q agent/tests` : réussi, 12 tests ;
- `docker compose config --format json | python3 demo/check_delivery_boundary.py` : réussi.

### Risques et limites

La cible `aaph-server`/`aaph-agent` n'est pas encore construite : le sprint fige
seulement son contrat. Aucun artefact final n'existe encore pour exécuter le
contrôle de packaging en situation de livraison. Le workspace Git contient de
nombreux fichiers non suivis et un dépôt imbriqué préexistant, laissé intact.

## Sprint 12 — bibliothèques Rust composables

État : implémenté et validé ; wrappers binaires historiques conservés jusqu'au sprint 15.

### Réalisé

- renommage des crates en `aaph-authority` et `aaph-pep` et mise à jour du workspace ;
- extraction des points d'entrée dans `run_from_env`, avec wrappers binaires minces de compatibilité ;
- constructeurs `AuthorityApp` et `PepApp` produisant des routers Axum sans socket ;
- configuration typée `PepAppConfig` et injection de l'horloge, du stockage et de la capability workspace ;
- séparation des traits `PermitDispatcher` et `ContainmentPropagator` ;
- isolation des effets derrière `OperationExecutor`, implémenté uniquement dans `aaph-pep` ;
- test d'architecture interdisant à Authority toute dépendance `cap-std`, `aaph-pep`, `Workspace` ou exécuteur.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 81 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `python3 -m pytest -q agent/tests` dans le venv WSL : réussi, 12 tests.

### Limites connues

Les processus restent temporairement nommés `authority-service` et `remote-pep`
pour préserver Docker Compose et le client Python, volontairement inchangés
pendant ce sprint. Ces wrappers sont marqués pour suppression au sprint 15.

## Sprint 13 — garde des clés et administration séparée

État : implémenté et validé.

### Réalisé

- remplacement du provisioning historique par `AAPH_AGENT_PUBLIC_KEY_FILE`, obligatoire et strictement validé avant le démarrage ;
- bootstrap fondé uniquement sur `PublicKeyValue`, avec empreinte calculée sans chargement ni reconstruction de clé privée agent ;
- séparation typée des configurations publique, secrète serveur, identité publique agent et administrative ;
- confirmation que seul le client agent monte `local-keys/agent/signing.key` ;
- déplacement de `demo/recover.py` vers `tools/aaph-admin/recover.py` et exclusion de `tools/` du contexte Docker ;
- retrait de l'outil administratif du `Dockerfile.agent` et garde interdisant `AAPH_ADMIN_SECRET` dans l'agent ;
- générateur documentant `signing.key` privé et `public.key` publiable, sans écrasement implicite, avec modes Unix 0600 et 0644 ;
- tests de démarrage avec clé publique seule, refus des clés absentes/invalides, montages Compose et contenu de l'artefact agent.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 83 tests sur Windows ;
- test Unix ciblé `development_key_generation_uses_minimal_permissions` : réussi sous WSL ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `python3 -m pytest -q agent/tests` : réussi, 15 tests ;
- `docker compose config` : réussi ;
- analyse du Compose rendu : réussie, aucune clé privée agent dans un service serveur et aucun secret administratif dans l'agent.

### Limites connues

Les wrappers et le nombre de services restent volontairement inchangés. La clé
privée d'autorité conserve son mécanisme de développement existant ; une garde
matérielle de production reste hors du périmètre de ce PoC.

## Sprint 14 — identifiants de permit, rejeu et idempotence d'effet

État : implémenté et validé.

### Réalisé

- `credential_id` est défini comme l'identifiant du permit ; chaque permit
  signé porte en plus un `jti`, un nonce CSPRNG d'au moins 128 bits et un
  `effect_operation_id`, générés indépendamment ;
- migration SQLite non destructive des permits et registre PEP durable des
  `jti`, nonces et opérations d'effet ;
- cycle fermé `RECEIVED`, `STARTED`, `COMPLETED`, `FAILED`, `AMBIGUOUS`, avec
  persistance avant exécution et du résultat avant réponse ;
- une opération `STARTED` trouvée au redémarrage devient `AMBIGUOUS` et n'est
  jamais rejouée automatiquement ;
- la même clé d'idempotence et le même digest rendent le résultat stocké sans
  nouvel effet ; un digest différent produit un conflit sans mutation ;
- les défaillances internes PEP exposent seulement le motif local
  `LOCAL_INTERNAL_FAIL_CLOSED` avec un statut HTTP 500/503 ;
- le client Python relaie sans modification tous les identifiants du permit.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 92 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `python3 -m pytest -q agent/tests` dans le venv WSL : réussi, 16 tests ;
- recherche statique : aucun `INSERT OR REPLACE` et aucune désactivation de
  validation TLS dans les composants concernés.

### Limites connues

Les registres de rejeu ne sont pas compactés. Une opération ambiguë exige une
résolution opérateur hors protocole et reste volontairement inexécutable. Le
profil local utilise un tenant fixe `NON_PRODUCTION_DEMO`. Le workspace Git
atypique et le dépôt imbriqué préexistants ont été conservés sans suppression.

## Sprint 15 — binaire serveur Rust unique

État : implémenté et validé.

### Réalisé

- ajout du crate `aaph-server`, unique binaire serveur de production, avec
  `main.rs`, `bootstrap.rs`, `public_api.rs` et `admin_api.rs` ;
- composition en mémoire de `aaph-authority` et `aaph-pep`, sans donner de
  capacité workspace au router Authority ;
- origine HTTPS publique commune pour sessions, propositions, effets, état,
  audit et santé globale ;
- listener HTTPS administratif séparé, adresse, TLS et secret configurés
  indépendamment du listener public ;
- deux stores SQLite conservés : `authority.db` et `pep.db` ;
- remplacement de la propagation HTTP par `ContainmentSink` interne : écriture
  Authority d'abord, application monotone PEP ensuite ;
- suppression des wrappers binaires `authority-service` et `remote-pep` ;
- migration de Compose, de l'image Rust, des configurations agent, de la PKI
  de développement et de la démonstration vers `aaph-server` ;
- commandes `--help`, `--version` et `healthcheck` sans chargement de secret.

### Validations

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 96 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `cargo test -p aaph-e2e --test quarantine_e2e -- --nocapture` : réussi, 2 tests ;
- `python3 -m pytest -q agent/tests` : réussi, 16 tests ;
- `docker compose config --quiet` : réussi ; services rendus : `aaph-server`, `agent` ;
- contrôle de frontière sur le Compose rendu : réussi ;
- inventaire Cargo : seul `aaph-server` est un binaire serveur ; `aaph-keygen`
  reste l'utilitaire local de génération de clés ;
- `aaph-server --help` et `aaph-server --version` : réussis ;
- certificat `aaph-server` régénéré et vérifié par OpenSSL, avec SAN
  `aaph-server`, `localhost` et `127.0.0.1` ;
- analyse syntaxique de `demo/run-attack.ps1` : réussie.

### Limites connues

Authority et PEP partagent désormais le domaine de panne du processus, bien
que leurs stores, routers et capacités restent séparés. Le lancement Docker et
la démonstration processus complète n'ont pas été exécutés pendant cette
validation ; aucune image ni aucun conteneur n'a été modifié. Le warning du
profil PowerShell utilisateur observé lors des commandes WSL est externe au
dépôt et n'a affecté aucun test. Aucun volume n'a été supprimé.

## Sprint 16 — agent Python modulaire et empaquetable

État : implémenté et validé, sauf construction PyInstaller indisponible.

### Réalisé

- remplacement de `agent/agent.py` par le paquet `aaph_agent`, séparant CLI,
  client HTTPS, primitives de signature, planificateurs et interface LLM locale ;
- configuration fermée à une seule `server_url`, utilisée pour la proposition
  puis l'effet PEP logique sur la même origine ;
- suppression du wrapper historique après migration des scripts ;
- entry point console `aaph-agent` déclaré dans `pyproject.toml` ;
- spec PyInstaller one-file sans données embarquées et dépendance de build
  verrouillée séparément ;
- aucune implémentation LLM réseau, opération workspace ou dépendance au secret
  administratif dans le paquet ;
- configurations, Dockerfile agent, démonstration, tests et documentation migrés.

### Validations

- installation éditable locale et `aaph-agent --help` : réussies ;
- installation complète depuis la source dans un venv vierge : réussie ;
- `python3 -m compileall -q agent/aaph_agent` : réussi ;
- `python3 -m pytest -q agent/tests` : réussi, 20 tests ;
- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 96 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- recherches statiques : aucune seconde URL dans l'agent et aucune
  désactivation TLS ;
- Docker Compose n'a pas été modifié pendant ce sprint.

### Limites connues

PyInstaller n'est pas installé dans l'environnement de validation : la
construction one-file n'a donc pas été exécutée et aucun résultat n'est
revendiqué. La spec produit un binaire propre à la plateforme de build, jamais
un binaire multi-plateforme. `local_llm.py` reste volontairement une interface
sans implémentation avant le sprint 17.

## Sprint 17 — planificateur IA local sans autorité

État : implémenté et validé ; test Ollama réel optionnel non exécuté.

### Réalisé

- protocole `Planner` commun produisant uniquement des `Action` structurées ;
- modes CLI `deterministic`, `adversarial-demo` et `local-llm` ;
- `LocalLlmPlanner` compatible Ollama sur loopback, modèle et endpoint
  configurables, timeout, réponse bornée et aucun retry ou fallback ;
- lecture du document par un effet AAPH préalablement permis avant transmission
  au modèle ; aucun permit, secret, budget interne ou chemin système transmis ;
- validation hostile de la sortie : JSON fermé, types stricts, action
  enregistrée, chemin relatif et destination externe interdite ;
- démonstration adversariale conservée, produisant volontairement une
  proposition hors scope ensuite confinée sans permit ;
- aucune exécution locale d'une proposition et aucun téléchargement de modèle.

### Validations

- `python3 -m compileall -q agent/aaph_agent` : réussi ;
- `python3 -m pytest -q agent/tests` : réussi, 26 tests et 1 test Ollama ignoré ;
- transports simulés : succès, non-JSON, action inconnue, taille, timeout sans
  retry et injection adversariale couverts ;
- `aaph-agent --help` : réussi ;
- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 96 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi.

### Limites connues

Le test réel Ollama est explicitement marqué optionnel et ignoré en CI ; aucun
serveur ni modèle local n'a été téléchargé ou lancé. Le modèle reste
probabiliste et hostile. L'endpoint HTTP loopback de démonstration ne fournit
pas une authentification ou une isolation de production.

## Sprint 18 — livraison Docker finale à deux conteneurs

État : implémenté et validé statiquement ; démarrage Docker non validé à cause
d'un accès réseau intermittent de BuildKit.

### Réalisé

- Compose réduit exactement aux services `server` et `agent` ;
- image serveur multi-stage ne livrant que `aaph-server`, et image agent ne
  livrant que le paquet Python ;
- séparation stricte des montages : bases, workspace, clé Authority, clé
  publique agent, politique, mandat, manifeste et TLS côté serveur ; clé privée
  agent, CA, configuration et tâche côté agent ;
- listener administratif distinct, publié sur localhost, dont le secret reste
  absent du conteneur agent ;
- conteneurs non-root, racine en lecture seule, capabilities supprimées,
  `no-new-privileges` et `tmpfs` borné ; aucun socket Docker, réseau hôte ou
  mode privilégié ;
- healthcheck HTTPS avec vérification par la CA ;
- contrôle automatisé du Compose rendu refusant toute capacité serveur,
  Authority, administrative, base ou workspace dans l'agent ;
- certificat serveur de développement étendu au SAN `server`.

### Validations

- `cargo fmt --all` puis `cargo fmt --all -- --check` : réussis ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 96 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `python3 -m compileall -q agent/aaph_agent` : réussi ;
- `python3 -m pytest -q agent/tests` : réussi, 28 tests et 1 test Ollama ignoré ;
- `docker compose config --format json` : réussi ; services rendus : `server`,
  `agent` ;
- contrôle de frontière sur ce Compose rendu : réussi ;
- régénération et vérification OpenSSL du certificat `aaph-server` : réussies,
  SAN `aaph-server`, `server`, `localhost` et `127.0.0.1`.

### Limites connues

`docker compose build server agent` a d'abord expiré pendant la résolution des
images de base. Une tentative ultérieure les a résolues, mais le téléchargement
de `cryptography` a expiré sur `files.pythonhosted.org`; BuildKit a alors annulé
la compilation Rust parallèle. Par conséquent `docker compose up`, l'état
healthy et le scénario agent one-shot ne sont pas revendiqués pour ce sprint.
Les anciens conteneurs arrêtés des noms historiques observés par `compose ps -a`
ne font pas partie de la configuration rendue. Aucun volume Docker n'a été
supprimé et aucun commit ou push n'a été effectué.

## Sprint 19 — tests black-box des deux exécutables

État : implémenté et validé.

### Réalisé

- harnais pytest lançant les vrais `aaph-server` et `aaph-agent`, sans mock des
  exécutables ni du transport ;
- environnement temporaire autonome : CA et certificat TLS, deux paires de
  clés, deux bases SQLite, configurations et workspace ;
- scénario légitime avec quatre effets et rapport réellement écrit ;
- scénario `adversarial-demo` lisant le document empoisonné et produisant une
  proposition externe réellement confinée sans permit ;
- refus de l'effet direct, de l'action post-confinement et de l'ancien permit
  par `E_EPOCH_STALE`, conformément à l'ordre des contrôles ;
- redémarrage sur les mêmes bases et preuve de persistance du confinement, du
  budget, des opérations, jti, nonces et audits ;
- récupération par l'outil opérateur configurable, obligation d'une nouvelle
  session et émission de quatre nouveaux permits sans collision ;
- ajout de l'événement `INSTANCE_RECOVERED` à la chaîne d'audit, avec test de
  régression Rust ;
- assertion globale de non-divulgation de `DEMO_SECRET_NOT_REAL` ;
- nettoyage limité au répertoire temporaire après succès, avec conservation
  automatique des artefacts et logs en cas d'échec.

### Validations

- référence sprint 18 : 96 tests Rust réussis, 28 tests Python réussis et 1
  test Ollama optionnel ignoré ;
- test Rust ciblé `recovery_requires_new_session` : réussi ;
- `cargo fmt --all` puis `cargo fmt --all -- --check` : réussis ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 96 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- `python3 -m compileall -q agent/aaph_agent tools/aaph-admin tests/black_box` : réussi ;
- `python3 -m pytest -q agent/tests` : réussi, 28 tests et 1 test Ollama ignoré ;
- `python3 -m pytest -q tests/black_box/test_two_executables.py` : réussi,
  10 tests, aucun test ignoré et aucun avertissement ;
- deux exécutions complètes réussies après correction : 10/10 en 578,95 s,
  puis 10/10 en 420,53 s avec contextes SSL explicites.

### Limites connues

La première compilation Linux sous WSL et `/mnt/c` est lente ; le harnais lui
accorde jusqu'à 15 minutes, tandis que les agents et requêtes restent bornés à
des délais courts. Deux répertoires temporaires des tentatives de diagnostic
échouées ont été volontairement conservés sous `/tmp` et leurs chemins ont été
affichés par pytest. Aucun volume ou conteneur Docker, aucune donnée utilisateur
et aucun service externe n'ont été modifiés. Aucun commit ni push n'a été fait.

## Sprint 20 — durcissement, packaging propre et livraison finale

État : implémenté et validé.

### Réalisé

- suppression des lanceurs runtime historiques et des configurations à deux
  URL dans `aaph-authority` et `aaph-pep`; `aaph-server` est le seul binaire
  serveur ;
- maintien des migrations non destructives et test de compatibilité des lignes
  SQLite existantes ; aucune base ni aucun volume utilisateur supprimé ;
- packaging natif par allowlist exacte vers deux exécutables, un guide, deux
  checksums et quatre fichiers de preuve publics ;
- refus automatisé des répertoires de développement, caches, bases, clés,
  certificats, logs, exports d'audit, workspaces et sorties de démonstration ;
- détection des clés privées locales connues dans l'ensemble du paquet ;
- documentation complète de l'installation, du provisionnement post-install,
  des deux scénarios, des preuves, de la récupération et du nettoyage ;
- installation explicite du fournisseur `ring` au démarrage du serveur, sans
  dépendre d'une activation transitive ;
- classification explicite des liens symboliques sortants en refus de ressource
  (403), avec test de régression existant désormais stable.

### Validations finales réelles

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace --all-targets --all-features` : réussi ;
- `cargo test --workspace --all-features` : réussi, 97 tests ;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` : réussi ;
- compilation Python : réussie ;
- `python3 -m pytest -q agent/tests` : 33 réussis, 1 Ollama optionnel ignoré ;
- `python3 -m pip check` : aucune exigence cassée ;
- `docker compose config` et contrôle de frontière : réussis, exactement
  `server` et `agent` ;
- `docker compose build server agent` : réussi pour les deux images ;
- black-box sprint 19 : 10 réussis en 405,05 s ;
- `demo/verify_delivery.py`, `sha256sum -c` et les deux commandes `--help` :
  réussis sur Linux x86_64.

### Contrôles non exécutés et limites

`cargo-audit`, `cargo-deny` et `pip-audit` sont absents ; ils n'ont pas été
installés silencieusement. `cargo tree --workspace --duplicates` a été inspecté.
Les artefacts ne sont ni signés, ni accompagnés d'une SBOM/provenance attestée,
ni reproductibles bit-à-bit. Authority et PEP restent logiquement séparés mais
partagent le processus `aaph-server`; une production devrait permettre leur
redéploiement séparé. Le profil demeure `NON_PRODUCTION_DEMO` et démontre le
confinement des effets, pas l'impossibilité d'influencer un LLM. Aucun commit,
tag, push, publication, suppression de volume ou suppression de base n'a eu lieu.
