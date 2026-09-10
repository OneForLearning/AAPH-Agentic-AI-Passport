# Rapport de validation de livraison

Profil : `NON_PRODUCTION_DEMO`  
Plateforme validée : Linux x86_64 sous WSL  
Date : 2026-09-10

Résultats finaux réellement obtenus :

- tests Rust du workspace : 97 réussis ;
- tests Python agent : 33 réussis, 1 test Ollama optionnel ignoré ;
- tests black-box à deux processus : 10 réussis, aucun ignoré ;
- formatage Rust, `cargo check` et Clippy avec `-D warnings` : réussis ;
- `docker compose config` et build des images `server`/`agent` : réussis ;
- allowlist, absence des clés locales connues et checksums : réussies ;
- vérification TLS active dans les tests black-box : réussie ;
- assertion de non-divulgation de la sentinelle de test : réussie.

Contrôles de vulnérabilités non exécutés : `cargo audit`,
`cargo deny` et `pip-audit` ne sont pas installés. Aucun outil n'a été installé
implicitement. `pip check` et l'inspection de `cargo tree --duplicates` ont été
exécutés ; `pip check` ne signale aucune exigence cassée.

Ce rapport ne contient ni logs runtime, ni export d'audit, ni clé, certificat,
configuration d'exécution, base SQLite ou contenu du workspace.
