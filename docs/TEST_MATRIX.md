# Correspondance exigences–tests

| Exigence | Preuve principale |
|---|---|
| Autorité issue uniquement du mandat | tests `aaph-core::policy` et `mandate` |
| Schémas fermés et entrées hostiles | tests `aaph-core::action` et routes contrôleur/PEP |
| Permit lié à audience, détenteur et digest | `every_critical_permit_field_is_covered_by_signature`, tests PEP |
| Nonce atomique et rejeu concurrent | `rejects_replay_sequential_and_concurrent` |
| Budget persistant entre sessions | tests SQLite et `budget_and_recovery_never_restore_old_authority` |
| Traversal, limites, destination externe | `rejects_paths_limits_destination_and_preserves_atomic_writes` |
| Confinement monotone, ancien permit invalide | tests routes/PEP et scénario `aaph-e2e` |
| Récupération sans restauration | `quarantine_is_idempotent_and_recovery_requires_admin_validation_and_new_session` |
| Journal chaîné | `audit_chain_detects_modification_deletion_and_permutation` |
| Injection sans lecture du faux secret | tests Python et `aaph-e2e` |
| TLS vérifié et CA épinglée | démarrage local/Compose, refus sans certificats |
| Conteneurs non-root et capacités supprimées | `docker compose config`, inspection Compose |

## Futures preuves black-box — migration à deux livrables

| Preuve | Critère observable |
|---|---|
| Inventaire `aaph-agent` | aucune route d'administration, clé d'autorité, base serveur ou donnée workspace dans l'artefact |
| Inventaire `aaph-server` | aucune clé privée agent ; seulement la clé publique provisionnée |
| Frontière workspace | lecture directe impossible depuis l'agent et depuis le module Authority |
| Effet sans permit | refus PEP sans mutation du workspace |
| Permit altéré/expiré/rejoué | refus PEP sans mutation et preuve d'audit |
| Compromission du planificateur | destination externe et ressource hors scope refusées, puis confinement |
| Séparation logique embarquée | aucun chemin Authority vers l'exécuteur hormis l'interface PEP typée |
| Crash entre émission et effet | credential durable, aucun rejeu automatique d'un résultat ambigu |
| Redémarrage/récupération | anciennes sessions, réservations, nonces et permits restent inutilisables |
| Packaging reproductible | les deux artefacts passent `check_delivery_package.py` et leur manifeste de fichiers est stable |
| Configuration de livraison | `check_delivery_boundary.py` refuse tout partage de clé privée agent |

## Livraison Docker finale — sprint 18

| Exigence | Preuve principale |
|---|---|
| Exactement deux services | analyse du Compose rendu par `check_delivery_boundary.py` |
| Agent sans capacité serveur | refus des montages, variables Authority/admin, bases et workspace par le contrôleur |
| Images minimales et distinctes | `test_delivery_dockerfiles_build_only_the_expected_runtimes` |
| Durcissement runtime | `docker compose config` : non-root, lecture seule, `cap_drop: ALL`, `no-new-privileges`, `tmpfs` borné |
| TLS du healthcheck | sous-commande `aaph-server healthcheck` avec CA explicitement montée |

## Processus black-box — sprint 19

| Preuve | Test processus réel |
|---|---|
| Quatre effets légitimes et rapport | `legitimate_task_cross_process` |
| Injection modifie la proposition, pas l'autorité | `injection_changes_proposal_but_not_authority` |
| Quarantaine sans permit | `malicious_proposal_receives_no_permit` |
| Effet direct sans permit | `direct_effect_without_permit_is_rejected` |
| Aucun effet interdit ni divulgation | `workspace_unchanged_after_attack` |
| Permit antérieur refusé par époque | `old_permit_rejected_after_quarantine` |
| Confinement, budget, opérations, jti, nonces et audit persistants | `restart_preserves_quarantine_budget_and_replay_state` |
| Récupération opérateur et nouvelle session | `recovery_requires_new_session` |
| Nouveaux identifiants sans collision | `post_recovery_legitimate_action_has_unique_ids` |
| Chaîne d'audit complète | `audit_chain_reconstructs_complete_scenario` |

La valeur sentinelle de test est recherchée dans stdout, stderr,
logs serveur, réponses HTTP, export d'audit et fichiers de sortie ; sa présence
fait échouer la suite.

## Preuves de composition — sprint 12

| Exigence | Preuve principale |
|---|---|
| Routers sans socket | `authority_router_builds_in_memory_without_socket`, `pep_router_builds_in_memory_without_socket` |
| Authority sans capability fichier | `authority_cannot_link_workspace_effect_capability` et absence de dépendance `cap-std`/`aaph-pep` |
| Effets confinés au PEP | `OperationExecutor` est implémenté par `WorkspaceOperationExecutor` dans `aaph-pep` |
| Propagation étroite | traits `PermitDispatcher` et `ContainmentSink` dans `aaph-authority` |
| Serveur Rust unique | `complete_server_builds_in_memory_with_public_agent_key_only` |
| Routes sans collision | `public_route_collision_is_impossible` |
| Listeners public/admin séparés | `public_and_admin_listeners_have_disjoint_routes` et vérifications 404 croisées |
| Confinement interne immédiat | `authority_containment_is_immediately_observed_by_pep` |
| Configuration agent mono-origine | `test_docker_configuration_matches_closed_schema`, `test_configuration_rejects_unknown_and_legacy_urls`, `test_agent_never_contacts_a_second_origin` |
| Frontière locale agent | `test_package_has_no_workspace_or_admin_capability` |
| Packaging agent | installation dans un venv vierge et `aaph-agent --help` |
| Sortie LLM hostile | `test_non_json_output_is_rejected`, `test_unknown_action_is_rejected_before_server_network`, `test_oversized_response_is_rejected` |
| Timeout sans retry | `test_model_timeout_stops_agent_without_retry` |
| Injection IA sans autorité | `test_adversarial_injection_creates_out_of_scope_proposal_without_secret`, `test_attack_demo_same_agent_is_contained_and_cannot_bypass_pep` |
| Panne PEP fail-closed | `pep_failure_after_containment_is_visible_and_fail_closed` |

## Preuves de garde des clés — sprint 13

| Exigence | Preuve principale |
|---|---|
| Bootstrap avec clé publique seule | `server_starts_with_agent_public_key_only` |
| Clé publique absente ou invalide | `server_rejects_missing_agent_public_key` |
| Aucun montage privé côté serveur | `agent_private_key_is_not_mounted_in_server` et analyse du Compose rendu |
| Aucun outil administratif dans l'agent | `agent_artifact_contains_no_admin_recovery_tool` |
| Aucun secret administratif dans l'agent | `test_agent_never_receives_admin_secret` |

## Preuves d'identifiants et de récupération d'effet — sprint 14

| Exigence | Preuve principale |
|---|---|
| Champs signés indépendants | `permit_binds_jti_nonce_and_effect_operation_id` |
| Persistance avant effet | `effect_operation_is_persisted_before_executor_call` |
| Résultat idempotent sans nouvel effet | `completed_operation_returns_stored_result_without_new_effect` |
| Crash `STARTED` fail-closed | `started_operation_becomes_ambiguous_after_restart`, `ambiguous_operation_is_never_replayed` |
| Rejeu durable | `jti_replay_rejected_after_restart`, `nonce_replay_rejected_after_restart` |
| Idempotence Authority concurrente | `concurrent_same_idempotency_key_consumes_budget_once` |
| Même clé, digest différent | `same_key_different_digest_mutates_nothing` |
| Migration sans perte | `migrations_on_existing_database_preserve_old_rows` |

## Livraison native — sprint 20

| Exigence | Vérification reproductible |
|---|---|
| Deux exécutables et preuves publiques uniquement | `python3 demo/verify_delivery.py dist` |
| Refus des états locaux et secrets | `agent/tests/test_delivery_checks.py` |
| Checksums couvrant exactement les deux binaires | `demo/verify_delivery.py` et `sha256sum -c` |
| Exécutables autonomes | les deux commandes `--help` dans `dist/` |
| Compatibilité fonctionnelle | suites Rust, agent et black-box sprint 19 |
| Image finale à deux services | `docker compose config` et `docker compose build server agent` |

Les audits de dépendances sont lancés seulement si les outils sont déjà
installés ; leur absence est consignée sans installation silencieuse.
