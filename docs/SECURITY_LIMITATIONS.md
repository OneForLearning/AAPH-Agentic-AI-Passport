# Limites de sécurité

`NON_PRODUCTION_DEMO` : ce dépôt démontre des invariants AAPH, pas une plateforme de production.

- Ed25519 seul remplace le profil hybride attendu par AAPH ; il n'y a ni HSM, rotation, révocation, transparence de clés, ni ancrage externe du journal.
- La CA et les certificats rustls sont locaux, partagés par les services et valides 30 jours. La CA est épinglée, mais sa clé reste sur la machine de démonstration.
- Le secret administratif est une variable d'environnement du seul serveur.
  L'administration utilise un listener et un port distincts, publiés seulement
  sur localhost en mode Docker ; il n'existe pas de mTLS opérateur.
- Le journal est tamper-evident, pas immuable face à un administrateur contrôlant SQLite et l'application. Export et métriques révèlent des métadonnées.
- Une petite fenêtre distribuée demeure entre confinement durable côté contrôleur et application au PEP. La métrique mesure le dernier aller-retour observé dans ce processus.
- Les réseaux Docker réduisent la connectivité accidentelle mais ne constituent pas une frontière de production. Une compromission root, Docker, hôte, service ou clé reste hors périmètre.
- Les `jti` et nonces ne sont pas compactés. Les opérations `AMBIGUOUS` exigent
  une résolution opérateur qui n'est pas automatisée dans ce PoC. SQLite
  n'apporte ni réplication, sauvegarde, chiffrement au repos, ni haute disponibilité.
- Le modèle local reste probabiliste et non fiable ; les tests CI utilisent le
  mode déterministe ou un transport simulé. Son endpoint loopback n'est pas un
  service authentifié. L'exécutable PyInstaller est spécifique à sa plateforme.
- Les artefacts sensibles sont ignorés. L'état Git du dossier de travail reste
  atypique : la majeure partie du PoC est non suivie et un ancien dépôt
  `AAPH-PoC/` est imbriqué ; aucune suppression automatique n'est effectuée.
- La livraison emploie exactement deux conteneurs : `agent` et `server`
  (ce dernier exécute `aaph-server`). Authority et
  PEP partagent donc un domaine de panne et une image, même si leurs stores,
  routers et capacités restent séparés. Cette composition n'est pas une
  isolation de processus de production.

## Revue finale

La recherche statique n'a trouvé aucun shell générique, `Command`, `eval`, `exec`, Docker socket, mode privilégié ou chemin direct du client Python vers le workspace. Les `unwrap`/`expect` observés sont dans les tests. Les frontières JSON sont fermées, les corps et effets sont bornés, les clients ont des timeouts, les secrets administratifs sont comparés en temps constant, et audience, détenteur, digest, dates, nonce et époques sont revérifiés au PEP.

## Limites de la livraison native

- Les exécutables sont propres à une plateforme. Les checksums ne sont ni une
  signature d'éditeur, ni une provenance SLSA, ni une SBOM signée, ni une preuve
  de reproductibilité bit-à-bit.
- La recherche des clés locales connues et marqueurs PEM ne remplace pas une
  analyse industrielle de secrets. La génération et la garde post-installation
  restent à la charge de l'opérateur.
- Le confinement des effets est testé ; l'absence d'influence sur le
  raisonnement d'un LLM n'est ni revendiquée ni démontrée.
