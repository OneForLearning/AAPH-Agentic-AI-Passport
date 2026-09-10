# Architecture

Le PoC sépare trois frontières de confiance. Aucun comportement métier n'est implémenté au sprint 0.

## Modèle de domaine fermé (sprint 1)

`aaph-core` contient des contrats indépendants du transport, du stockage et du système de fichiers. Les identifiants critiques sont des newtypes distincts. `RawActionProposal` conserve temporairement un nom d'action hostile et borné ; seule une conversion explicite et faillible produit une `CanonicalActionRequest` dont l'action appartient à `ActionKind`.

Les valeurs JSON des actions, états, décisions et codes de motif sont stables et les variantes inconnues sont refusées. Les objets reçus aux frontières utilisent `deny_unknown_fields`. Les timestamps sont des secondes Unix signées explicitement typées `UtcTimestamp`.

Une instance suit `ACTIVE -> CONTAINED -> RECOVERY_PENDING -> ACTIVE`, avec révocation depuis tout état non révoqué. Le confinement incrémente une époque par addition vérifiée. Le retour à l'état actif consomme un marqueur `RecoveryValidation`. Une session suit `CREATED -> ACTIVE`, puis devient définitivement `TERMINATED`, `EXPIRED` ou `REVOKED`.

Ces contrats ne réalisent encore aucune décision de politique, persistance de budget ou exécution distante.

## Canonicalisation et artefacts signés (sprint 2)

Les objets signés sont sérialisés selon JSON Canonicalization Scheme RFC 8785 par `serde_jcs`. Le transcript contient la longueur du domaine sur 32 bits, le domaine NUL-terminal, la longueur de l'objet canonique sur 64 bits, puis ses octets. Cette structure interdit les concaténations ambiguës.

SHA-384 produit les empreintes. Les signatures Ed25519 couvrent les propositions d'action, permits et événements de confinement dans des domaines distincts. Clés publiques, signatures et empreintes emploient exclusivement base64url sans padding, avec décodage strict et longueur fixe.

`ExecutionPermit` engage l'identité complète de l'agent et de sa session,
l'empreinte du détenteur, l'audience PEP, le digest de requête, les deux époques,
`jti`, `nonce`, `effect_operation_id`, la réservation de budget et la
version/empreinte de politique. Les trois identifiants sont indépendants et
couverts par la signature. Une politique temporelle configurable, de 60 secondes
par défaut, est appliquée à la construction et à chaque vérification.

Les enveloppes portent `NON_PRODUCTION_DEMO`. Ed25519 seul ne satisfait pas le profil cryptographique hybride attendu d'un système AAPH de production.

## Autorité, PDP et budget (sprint 3)

Le calcul reste pur et sépare six étapes : validation temporelle et structurelle du `Mandate`, création de `ValidatedAuthority` depuis ce mandat uniquement, intersection avec `AgentDefinition` et `BehavioralManifest`, évaluation par `DemoPolicy`, réservation dans `BudgetLedger`, puis émission future d'un permit. Aucun attribut d'identité, clé, modèle ou fournisseur ne peut ajouter une action, une ressource ou une finalité.

La politique configurable conserve des racines fermées : lecture, liste et SHA-256 sous `inbox/`, écriture sous `output/`. Sa configuration peut désactiver des actions, restreindre les finalités et réduire les plafonds de lecture/écriture, mais ne peut déplacer ces racines. Le contrôleur refuse les chemins logiques absolus, vides, avec `.`, `..`, NUL, antislash ou composant ambigu. La résolution des liens symboliques reste réservée au PEP.

`PolicyOutcome` distingue permission, refus ordinaire, confinement demandé et erreur interne fail-closed. Une mauvaise signature non attribuable reste un refus ; rejeu, expiration ou incohérence de digest ne demandent un confinement que lorsque l'identité a été établie de manière sûre.

`BudgetLedger` suit séparément `action_count`, `read_bytes` et `write_bytes`. Une demande disponible devient réservée, puis engagée ou libérée. La fermeture d'une session libère uniquement ses réservations en attente ; la consommation engagée demeure dans le même registre pour les sessions suivantes.

## Persistance SQLite et audit chaîné (sprint 4)

`aaph-authority` utilise des repositories étroits pour définitions/mandats, états, budgets, décisions et audit. L'implémentation SQLx exécute la migration versionnée au démarrage et active `PRAGMA foreign_keys = ON` sur chaque connexion. Les colonnes JSON canoniques conservent les objets fermés tandis que les identifiants, jointures, états, dates, époques, compteurs et digests nécessaires aux invariants restent dédiés et contraints.

Les réservations, engagements, libérations, fermetures de session, paires requête/décision et ajouts d'audit utilisent des transactions. Les opérations concurrentes de budget commencent par `BEGIN IMMEDIATE`; l'époque de confinement emploie une mise à jour conditionnelle sur la valeur attendue. Le schéma permet au sprint suivant de grouper état d'instance, époque, sessions, réservations et événements dans une seule transaction.

Chaque `AuditEvent` engage sa séquence, son type, son sujet, le digest SHA-384 du payload métier, le hash précédent, son timestamp et son hash courant sous le domaine `AAPH-POC-AUDIT-EVENT-V1\0`. Le premier événement référence le genesis constant documenté comme 48 octets zéro encodés en base64url. La vérification refuse les ruptures de séquence ou de hash, ce qui révèle modification, insertion, suppression intermédiaire et permutation.

## Agent Python local

L'agent propose des actions structurées. Son `Planner` étroit est remplacé dans
ce sprint par un planificateur déterministe ; un futur planificateur local peut
implémenter la même interface sans changer les protocoles. L'agent signe JCS
avec sa seule clé d'instance, demande une session et présente au PEP uniquement
les permits retournés. Il ne connaît que les URL publiques et ne possède aucun
credential du workspace ou de l'autorité.

## Contrôleur AAPH Rust

Le profil local versionné d'identifiants est `AAPH-POC-ID-UUIDV7-1` : les
identifiants produits par l'autorité sont des UUIDv7 RFC 9562 canoniques en
minuscules. Les nonces sont 128 bits CSPRNG encodés en base64url sans padding.
Dans ce profil, `credential_id := permit_id`, `idempotency_key := request_id` et
`tenant := NON_PRODUCTION_DEMO`. `permit_id`, `jti` et `effect_operation_id`
sont trois UUIDv7 générés séparément ; le nonce est généré séparément par le
CSPRNG.
Ce profil `NON_PRODUCTION_DEMO` n'est pas un registre `OperationalProfile`
signé et ne revendique pas `VERIFIED-INTEROPERABLE`.

`aaph-authority` est la bibliothèque de décision. Son API Axum versionnée sépare
les handlers, l'orchestrateur, l'horloge injectée et les repositories. Le body
est borné avant désérialisation ; les schémas fermés, états, dates, liaison de
clé et rejeu sont vérifiés avant canonicalisation et calcul d'autorité. Un
permit court n'est signé qu'après réservation transactionnelle du budget et
engage le digest exact de la proposition. Le dispatcher injecté au sprint 5 est
un faux déterministe sans effet sur le workspace.

## PEP/exécuteur Rust distant

`aaph-pep` est l'unique bibliothèque possédant la capability d'effet. Il vérifie indépendamment la clé
d'autorité, l'audience, le temps, le digest canonique, le détenteur, les
époques, le `jti` et le nonce avant de revérifier l'action. SQLite conserve
époques, identifiants consommés, événements de confinement et opérations
d'effet. Une opération passe par `RECEIVED`, puis `STARTED` avant tout appel à
l'exécuteur, et `COMPLETED` avec résultat et digest avant la réponse. Un état
`STARTED` trouvé au redémarrage devient `AMBIGUOUS` et n'est jamais rejoué sans
résolution opérateur. Le workspace est
ouvert une fois comme capacité `cap-std`; lecture et écriture sont bornées,
les symlinks sortants sont refusés par la résolution capability-based et les
rapports sont renommés atomiquement depuis un temporaire du même répertoire.

## Bibliothèques composables (sprint 12)

`aaph_authority::AuthorityApp` et `aaph_pep::PepApp` construisent leurs routers
Axum en mémoire sans ouvrir de socket. `aaph-server` est l'unique binaire serveur
et compose un router public commun avec un router administratif servi par un
listener distinct. Les bases `authority.db` et `pep.db` restent séparées.
`aaph-authority` ne dépend ni de `aaph-pep` ni de `cap-std`; seule `aaph-pep`
compose `OperationExecutor` avec `Workspace`. La propagation de confinement
utilise `ContainmentSink` : l'écriture Authority précède l'application monotone
et l'acquittement PEP, sans appel HTTP interne.

## Agent local modulaire (sprint 16)

Le paquet `aaph_agent` sépare CLI, protocole HTTPS, signature, planification et
future interface LLM locale. Sa configuration fermée contient une unique
`server_url`; propositions et effets utilisent donc nécessairement la même
origine. Le paquet ne connaît aucun chemin workspace, base serveur, secret
administratif ou clé privée d'autorité. `LocalLlmPlanner` appelle uniquement un
endpoint HTTP loopback compatible Ollama, avec timeout, réponse bornée et aucun
retry. Le document fourni au modèle provient d'une lecture préalablement permise
par AAPH. La sortie hostile est validée comme JSON fermé avant de devenir une
proposition ; elle ne déclenche jamais d'effet local.

## Garde des clés et administration (sprint 13)

Authority reçoit uniquement la clé publique agent via
`AAPH_AGENT_PUBLIC_KEY_FILE`; son absence ou son invalidité interdit le
démarrage. Le bootstrap calcule l'empreinte directement depuis ce type public
et ne peut reconstruire une clé privée. La configuration runtime sépare les
paramètres publics, les secrets cryptographiques du serveur, l'identité publique
agent et le secret administratif. Seul le processus agent monte
`local-keys/agent/signing.key`. L'outil de récupération est livré séparément
sous `tools/aaph-admin/` et est exclu du contexte Docker.

## Quarantaine et récupération (sprint 7)

Une décision grave authentifiée déclenche sous verrou SQLite l'incrément unique
de `containment_epoch`, la terminaison de toutes les sessions et la libération
de leurs réservations. L'événement signé est envoyé au PEP et son acquittement
est attendu. Le contrôleur reste confiné si cet envoi échoue. La récupération
passe par `RECOVERY_PENDING`, exige un secret et une validation nouvelle,
propage l'époque, puis revient à `ACTIVE` sans restaurer d'ancien artefact.

La linéarisation écrit l'époque du contrôleur avant la propagation, puis le
cache PEP avant l'acquittement. Un effet déjà linéarisé au PEP avant cette
seconde écriture peut finir : cette petite fenêtre distribuée demeure.

```text
agent Python ── proposition hostile ──> contrôleur AAPH
                                             │
                                      permit borné
                                             ▼
                                      PEP/exécuteur ──> workspace confiné
```

## Transport et livraison à deux conteneurs (sprint 18)

Les listeners Axum de `aaph-server` terminent TLS via rustls et l'agent épingle
la CA. Compose contient exactement `server` et `agent`. Le serveur seul reçoit
les deux volumes SQLite, le workspace, la clé Authority, la clé publique agent,
les configurations de décision et ses certificats TLS. L'agent reçoit seulement
sa clé privée, la CA, sa configuration et la tâche choisie. Les conteneurs sont
non-root, en lecture seule, sans capability ni élévation ; les écritures sont
bornées par volumes ou `tmpfs`. Le listener administratif est distinct et son
secret n'est jamais transmis à l'agent. Les réseaux Docker ne constituent pas
une frontière de production.

## Packaging natif à deux exécutables (sprint 20)

La surface de livraison est réduite à `aaph-server-<plateforme>` et
`aaph-agent-<plateforme>`. Le premier compose les bibliothèques Authority et PEP
dans un même processus, tout en maintenant routers, stores et capacités
logiquement distincts. Le second ne possède que le protocole client et la
capacité de signer comme agent. Une allowlist crée séparément les exécutables,
le guide, les checksums et des preuves publiques ; aucun arbre source ou état
runtime n'est copié.

Le partage de processus n'est pas une frontière d'isolation. Une architecture
de production doit pouvoir redéployer Authority et PEP séparément et protéger
leur canal de confinement/effet par une identité de service adaptée. Ce profil
reste `NON_PRODUCTION_DEMO`.
