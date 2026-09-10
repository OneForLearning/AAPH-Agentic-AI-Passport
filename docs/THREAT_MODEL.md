# Modèle de menace

## Garde cryptographique

La clé privée agent appartient exclusivement au client agent. Authority reçoit
sa seule clé publique publiable et refuse tout provisioning manquant ou
malformé. Le PEP ne reçoit que la clé publique Authority. Le secret
administratif et l'outil de récupération restent hors de l'environnement et de
l'artefact agent. Les contrôles de livraison analysent la configuration Compose
rendue afin de détecter tout futur montage croisé ou secret administratif.

Le PoC protège le workspace distant, les mandats, les budgets cumulés et l'intégrité des décisions et permits. Il doit échouer fermé face aux entrées ou états inconnus.

## Menaces incluses

- **Donnée hostile lue par l'agent** : l'attaquant contrôle un document et tente de détourner les propositions de l'agent. Toute sortie reste non fiable et sans autorité propre.
- **Path traversal** : une action tente un chemin absolu, `..`, un préfixe ambigu, un octet NUL ou un lien symbolique sortant du workspace. Le PEP devra canonicaliser et refuser le chemin.
- **Accès direct au PEP** : le PEP devra exiger et revérifier un permit valide pour chaque effet, même si l'agent ou le contrôleur est contourné.
- **Rejeu de permit** : audience, nonce à usage unique, dates, digest et époques devront être vérifiés indépendamment par le PEP.
- **Dépassement cumulatif** : la consommation devra persister entre sessions afin d'empêcher le fractionnement d'un budget ; confinement et récupération ne devront jamais la réinitialiser.

## Hors périmètre

Sont exclues la compromission root du contrôleur, la compromission root du PEP et la compromission des clés d'autorité. Le sprint 0 documente les exigences mais n'implémente encore aucune mitigation.

## Hypothèses cryptographiques du PoC

Le sprint 2 protège l'intégrité des artefacts par canonicalisation RFC 8785, SHA-384, séparation de domaines et Ed25519. Il ne fournit ni profil hybride post-quantique, ni rotation, révocation ou protection matérielle des clés. Les clés de démonstration restent locales et hors Git ; une compromission de clé demeure hors périmètre.

## Atténuation et attribution du risque

Le sprint 3 garantit qu'une définition d'agent, un manifeste ou une politique ne peut créer un droit absent du mandat validé. Toute erreur ou décision indéterminée échoue fermée. Traversal, ressource hors scope, destination externe et action inconnue authentifiée demandent un confinement. Une anomalie de signature, de rejeu ou d'expiration non attribuable de façon sûre reste un refus sans sanction d'instance.

Les plafonds cumulés incluent consommation et réservations. Fermer ou recréer une session ne réinitialise jamais la consommation. Ce registre reste en mémoire dans ce sprint ; sa persistance durable sera traitée ultérieurement.

## Garanties et limites du stockage

Le sprint 4 rend les invariants de budget transactionnels et prévient les lost updates par verrou d'écriture immédiat ou comparaison d'époque. Les références orphelines, valeurs négatives, états inconnus et dépassements de capacité sont refusés par le schéma puis revérifiés lors de la reconstruction des types.

Le journal chaîné est seulement tamper-evident : une altération qui ne recalcule pas toute la suite est détectée, mais un administrateur root contrôlant la base et tout ancrage externe peut réécrire ou tronquer l'historique. Aucun secret privé n'est stocké ; seules les clés publiques et empreintes ont une colonne prévue.

## Frontière HTTP du sprint 5

Les corps sont limités avant parsing et Serde refuse les champs inconnus. Une
proposition doit être signée par la clé publique liée à l'instance active et à
une session active non expirée. Les identifiants de requête sont uniques. Une
erreur inconnue échoue fermée et les réponses ne divulguent qu'un `ReasonCode`.
Le service n'exécute aucun effet : le dispatcher est un faux jusqu'au sprint 6.
Le profil de clés de démonstration et l'absence de TLS intégré restent hors des
garanties de production.

## Frontière d'effet du sprint 6

Le PEP ne fait confiance ni au verdict du contrôleur ni aux chemins reçus. Il
rejoue toutes les vérifications critiques et consomme le nonce par insertion
SQLite unique avant l'effet. Les chemins absolus, traversals, NUL, séparateurs
Windows et encodages `%` ambigus sont refusés. `cap-std` empêche une résolution
de symlink hors capacité. Aucune erreur ne retourne le contenu d'un fichier.
Les nonces expirés ne sont volontairement pas nettoyés dans ce PoC, ce qui
évite toute réactivation au prix d'une croissance de la table.

## Course de confinement

Le confinement local persiste si le PEP est indisponible ; la réponse expose
alors `containment_propagation_incomplete`. Le PEP applique les époques de
manière monotone et acquitte leurs répétitions. La fenêtre résiduelle se situe
entre l'écriture au contrôleur et l'application au PEP. Le test local mesure
application PEP–premier rejet sous une seconde, sans garantie de latence réseau.

La récupération utilise un secret d'environnement comparé en temps constant
et localhost par défaut. C'est une simplification de démonstration, pas un
mécanisme administratif de production.

## Rejeu, idempotence et crash d'effet

Chaque permit lie par signature trois identifiants indépendants : `jti`, nonce
et `effect_operation_id`. Le PEP consomme atomiquement `jti` et nonce, puis
persiste l'opération en état `RECEIVED` et `STARTED` avant d'appeler
l'exécuteur. Le résultat et son digest sont persistés avant la réponse. Une
opération restée `STARTED` après redémarrage devient `AMBIGUOUS` et n'est
jamais rejouée automatiquement : l'effet a pu avoir lieu sans que son résultat
ait été durablement enregistré. Une erreur interne locale retourne un statut
HTTP 500 ou 503 et le motif non normatif `LOCAL_INTERNAL_FAIL_CLOSED`, jamais
le code protocolaire `E_INTERNAL_FAIL_CLOSED`.

## Injection indirecte démontrée

Le mode `local-llm` rend explicite qu'un modèle peut suivre une instruction
injectée. Il ne reçoit ni permit, clé serveur, secret administratif, budget
interne ou chemin système. Sa réponse bornée est traitée comme hostile : JSON
fermé, action enregistrée, types stricts et chemin relatif. Une proposition
adversariale signée ne gagne aucune autorité et reste soumise à Authority puis
au PEP. Aucun modèle n'est téléchargé automatiquement et aucun fallback
permissif n'est prévu.

La fixture hostile est lisible sous `inbox/`, mais sa proposition de traversal
et d'exfiltration n'acquiert aucun droit grâce à l'identité légitime qui la
signe. Le contrôleur répond `QUARANTINE`, n'émet aucun permit, incrémente
l'époque et termine la session. Le faux secret demeure hors scope et les
tentatives directe et par rejeu échouent au PEP. Le planificateur vulnérable est
une simulation explicitement opt-in : marqueur exact, JSON fermé, aucune
évaluation de code, commande ou sortie réseau.

## Transport et conteneurs du sprint 10

TLS rustls protège les composants avec une CA de développement explicitement épinglée ; aucune désactivation de validation n'est exposée. Les corrélations sont générées côté serveur et les logs excluent contenu, clés et permits. Les conteneurs non-root, en lecture seule et sans capabilities réduisent l'exposition accidentelle, mais ni Docker ni TLS ne corrigent une compromission de l'hôte, d'une clé ou d'un processus privilégié. Les limites résiduelles sont dans `docs/SECURITY_LIMITATIONS.md`.

## Composition serveur du sprint 15

Le binaire unique ne fusionne pas les autorités logiques. Le router public ne
reçoit aucune capacité workspace et délègue `/v1/effects/execute` au router PEP.
Le listener administratif est distinct du listener public. Authority écrit le
confinement avant d'appeler le `ContainmentSink` interne ; une panne du sink est
visible et ne restaure aucune autorité. Le partage d'un processus réduit
l'isolation opérationnelle et demeure une limite explicite du PoC.

## Menaces liées aux artefacts de livraison

Le générateur de livraison part d'une allowlist exacte et refuse les répertoires
de développement, bases, clés, certificats, logs, exports d'audit, workspaces et
sorties de démonstration. Les checksums détectent une modification accidentelle
après génération, mais ne constituent ni une signature de release ni une chaîne
d'approvisionnement attestée. Les clés privées locales connues sont recherchées
dans chaque fichier livré.

Les clés, certificats et configurations restent des entrées post-installation.
Une compromission de leur mécanisme de provisionnement ou de la machine de build
reste hors du modèle. L'injection peut influencer le raisonnement du LLM ; la
garantie démontrée est que cette influence ne devient pas un effet hors mandat.
