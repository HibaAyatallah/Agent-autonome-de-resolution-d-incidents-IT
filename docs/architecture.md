# Architecture proposée — Phase 1

## Objectif

Construire un prototype modulaire qui reçoit des alertes, collecte des éléments de diagnostic, produit une explication traçable, propose une action contrôlée et vérifie le résultat. Les agents échangent des objets Pydantic structurés dans un état d'incident partagé.

## Architecture logique

```text
Dataset / API utilisateur / collecteur local
                    |
             Agent coordinateur
          (normalisation, priorité, ID)
                    |
     +--------------+----------------+
     |              |                |
  Agent Logs    Agent Système   Agent Réseau
     |              |           (DNS/connectivité)
     +--------------+----------------+
                    |
       Agent Sécurité (signaux locaux)
                    |
   Agent de raisonnement déterministe
    (règles + incidents similaires)
                    |
        Plan structuré avec preuves
                    |
       Approbation humaine requise
                    |
 Agent Action (allowlist, simulation d'abord)
                    |
 Agent Vérification + nouvelle collecte
                    |
       Mémoire persistante / API / UI
```

Le coordinateur dirige un workflow explicite avec limites de tentatives et délais. Les agents spécialisés peuvent diagnostiquer en parallèle, mais ils ne s'appellent pas directement entre eux. La décision finale contient les observations, leur source, la cause probable, le niveau de confiance et les prochaines étapes.

## Choix technologiques

- **Backend :** Python 3.11+, FastAPI et Pydantic pour l'API et les contrats structurés.
- **Orchestration :** workflow Python explicite à états, avec étapes, timeout, reprise bornée et approbation humaine. Pour cette première version, cela évite de rendre l'exécution dépendante d'un framework d'agents ou d'un LLM.
- **Diagnostic :** règles et seuils reproductibles en premier ; interface LLM optionnelle ensuite. Une sortie LLM ne peut jamais déclencher directement une commande.
- **Données :** pandas/openpyxl pour ingérer le classeur ; SQLAlchemy avec SQLite en développement local, compatible avec un passage à PostgreSQL.
- **Monitoring :** psutil pour les ressources de la machine qui exécute le prototype ; contrôles réseau limités à DNS/connexion configurés.
- **Interface prévue :** React + TypeScript + Vite consommant REST, puis WebSocket pour les événements live.
- **Tests et qualité :** pytest et Ruff.

## Ce que le dataset permet réellement

L'archive contient `results.xlsx` :

- `Datos finales` : 311 lignes × 6 colonnes, sans valeurs manquantes dans les 311 lignes observées. Champs : `acknowledged_time`, `completion_time`, `send_analysis_time`, `created_at`, `type`, `payload`.
- `Hoja 5` : une synthèse de temps et un total d'alertes ; ce n'est pas une table d'événements à concaténer avec la feuille principale.
- Les payloads sont des alertes JSON. Types observés : 303 `log`, 8 `usage`. Alertes : 282 `SSH Authentication Failure`, 20 `DatasourceNoData`, 4 `CPU Usage`, 2 `RAM Usage`, 1 `Network Usage`, 1 `DatasourceError`, 1 `Server Down Detection`. Les 311 portent le statut `firing`.
- Les colonnes temporelles sont des durées, mais l'unité n'est pas documentée explicitement dans le classeur ; l'ingestion conservera les valeurs brutes et indiquera l'unité comme inconnue jusqu'à confirmation de la source.

Le dataset n'apporte pas les valeurs numériques historiques de CPU/RAM/disque, les journaux bruts complets, les mesures réseau détaillées, les corrections tentées ni la preuve de résolution. Il servira à tester l'import, la normalisation, le classement d'alertes et les statistiques de délai. La collecte locale et la simulation couvriront les dimensions absentes, en étant étiquetées séparément des données observées.

## Garde-fous de remédiation

1. L'agent de raisonnement renvoie un plan typé ; les arguments sont validés contre une allowlist.
2. Le mode initial est `dry-run` et les actions sont simulées.
3. Les actions sensibles exigent une approbation humaine explicite.
4. Aucun shell arbitraire n'est exposé aux agents ou au LLM.
5. Chaque essai est journalisé ; délais, nombre de répétitions et permissions sont bornés.
6. Une résolution n'est déclarée qu'après observation positive par l'agent de vérification.

## Structure initiale créée

```text
backend/src/incident_response/
  api/             routes HTTP (health check initial)
  agents/          agents spécialisés
  dataset/         import et normalisation du classeur
  memory/          accès aux incidents persistés
  monitoring/      métriques et contrôles live
  orchestration/   workflow et état partagé
  reasoning/       règles et synthèse des preuves
  remediation/     allowlist, approbations et exécution contrôlée
  schemas/         contrats Pydantic
  verification/    contrôles après action
data/raw/          données source locales, ignorées par Git
data/processed/    données normalisées locales, ignorées par Git
frontend/src/      future interface React
tests/             tests unitaires et d'intégration
docs/              architecture et documentation
```

## Démarrage du squelette backend

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn incident_response.main:app --app-dir backend/src --reload
```

La route initiale `GET /api/v1/health` vérifie seulement que l'API démarre. Les fonctionnalités métier seront ajoutées après validation de cette architecture.

## Phase 2 — Ingestion et prétraitement

Le module `incident_response.dataset.ingest` lit directement l'archive ZIP ou un classeur `.xlsx`, vérifie la feuille et les colonnes requises, analyse le profil des deux feuilles, puis normalise les alertes de `Datos finales`. Il accepte les payloads JSON encodés une ou deux fois, écarte les champs IP/instance et masque les adresses IPv4 apparaissant dans le texte de résumé ou de description. L'horodatage de fin sentinelle `0001-01-01` est traité comme une fin absente.

Le traitement produit localement :

- `data/processed/alerts.jsonl` — un événement normalisé par ligne ;
- `data/processed/inspection_report.json` — schéma, valeurs manquantes, comptages d'alertes et statistiques des durées.

Le ZIP source reste dans `data/raw/source_dataset.zip` et les données source/traitées sont exclues de Git. Depuis la racine du projet, après installation décrite plus haut :

```powershell
python -m incident_response.dataset
python -m unittest discover -s tests/unit -v
```

Le pipeline ne suppose ni unité pour les durées, ni niveau de sévérité, ni résolution. Ces champs restent inconnus tant que la source ne les établit pas.

## Phase 3 — Surveillance et détection

`incident_response.monitoring` collecte en lecture seule les pourcentages CPU/RAM/disque, la mémoire et l'espace disque disponibles, ainsi qu'une courte liste des processus les plus consommateurs de mémoire. Les règles produisent des alertes `warning` ou `critical` selon les seuils configurés dans `.env`. Les valeurs par défaut sont 80/95 % pour CPU et 85/95 % pour RAM et disque.

Les contrôles réseau sont des résolutions DNS et connexions TCP vers les seules cibles configurées par `INCIDENT_NETWORK_TARGETS`, au format `nom=hôte:port`. La liste vide n'effectue aucun contrôle externe. Aucun `ping`, shell ou autre commande arbitraire n'est lancé. La route `GET /api/v1/monitoring/snapshot` fournit un instantané à l'interface, et `python -m incident_response.monitoring --interval 5` émet des instantanés périodiques en JSON. Le module `simulation.py` exécute les mêmes règles sur des métriques injectées, sans lire ni modifier la machine.

Avant utilisation, copier `.env.example` vers `.env`, ajuster les seuils et éventuellement configurer une ou plusieurs cibles TCP contrôlées. Les seuils sont validés : chaque seuil d'avertissement doit être inférieur au seuil critique. Le monitoring ne lance aucune correction.

Vérification de phase : la suite pytest couvre les seuils, les alertes CPU/RAM/disque, les échecs et succès de vérification TCP simulés, la configuration, la simulation et la collecte réelle de métriques via le gestionnaire de route. Ruff vérifie le style. L'environnement d'exécution de Codex bloque les sockets locales de `TestClient`; les tests d'API valident donc l'enregistrement OpenAPI et appellent le gestionnaire directement plutôt que d'ouvrir un port HTTP local.

## Phase 4 — Agents spécialisés

Les agents `LogsAgent`, `SystemAgent`, `NetworkAgent` et `SecurityAgent` sont des composants Python indépendants. Chacun reçoit des données normalisées ou un instantané, puis retourne un `AgentReport` Pydantic contenant statut, nombre d'entrées, constats, sévérité, preuves et limites. Aucun agent n'exécute de commande ni ne modifie le système.

- **Logs :** regroupe les alertes du dataset par nom et distingue signaux SSH, erreurs de source et autres alertes. Le rapport rappelle qu'il s'agit d'alertes, pas des lignes de logs ou du nombre exact d'erreurs sous-jacentes.
- **Système :** expose les alertes de ressource existantes avec la mesure observée et le seuil associé.
- **Réseau :** examine uniquement les cibles DNS/TCP configurées ; une liste vide retourne `no_data`, jamais « réseau sain ». Un échec isolé est un avertissement, car il ne permet pas de distinguer une panne réseau d'un service indisponible.
- **Sécurité :** signale les alertes d'échecs SSH pour vérification manuelle, sans confirmer une attaque ni révéler des adresses source. Un décompte d'alertes n'est pas interprété comme un décompte de tentatives.

Les rapports utilisent les contrats de `agents/models.py`; l'orchestration et l'agrégation des rapports seront ajoutées en phase 5.

## Phase 5 — Coordination et workflow

`CoordinatorAgent` reçoit un `IncidentInput`, initialise `IncidentWorkflowState`, classe les signaux présents et distribue le même contexte structuré aux quatre agents dans un `ThreadPoolExecutor`. Les agents sont indépendants ; seuls leurs rapports typés sont agrégés. Les erreurs sont isolées par agent, les exceptions transitoires donnent lieu à un retry (deux tentatives par défaut, maximum configurable jusqu'à trois), et chaque tâche a un délai maximal. Le résultat partiel est marqué `degraded` si un agent reste indisponible.

La priorité initiale suit une règle explicite : P1 si un constat est critique, P2 si au moins un constat est un avertissement, P3 si des données ont été analysées sans avertissement, et `unassessed` si aucun agent n'a pu obtenir de données. L'absence de données n'est donc pas interprétée comme une faible priorité. Ce triage n'est pas une cause racine. Les événements horodatés de réception, triage, distribution et retour des agents composent la timeline.

La route `POST /api/v1/incidents/diagnose` prend `origin`, une description, éventuellement les alertes normalisées et/ou un `monitoring_snapshot`. Les alertes `usage` du dataset sont transmises à l'agent Système comme déclarations du système source ; elles ne sont pas transformées en valeurs CPU/RAM brutes. Aucun incident n'est encore persisté (phase mémoire ultérieure) et aucune action de remédiation n'est exécutée.

Exemple minimal de requête :

```json
{
  "origin": "dataset",
  "description": "Alertes d'échecs d'authentification SSH",
  "alert_records": [
    {
      "source_type": "log",
      "alert_name": "SSH Authentication Failure",
      "summary": "La source signale des échecs SSH.",
      "source_record_id": "Datos finales:2"
    }
  ]
}
```

Envoyer cette requête à `POST http://127.0.0.1:8000/api/v1/incidents/diagnose` renvoie un `IncidentAssessment` avec la priorité P2, les quatre rapports d'agents, les catégories et l'historique des étapes. Sans mesures réseau/système, les rapports concernés disent `no_data`.

Vérification de phase : les tests couvrent la priorité P1/P2/P3/non évaluée, l'agrégation des alertes dataset, l'absence de données, les retries, les erreurs et le timeout isolé d'un agent. Les 31 tests passent et Ruff ne signale aucun problème. Le parcours de diagnostic sur les 311 alertes normalisées retourne les catégories logs/réseau/sécurité/système, une priorité P2 et sept constats ; ce résultat vérifie les règles de code et ne constitue pas une mesure de performance prédictive.

## Phase 6 — Raisonnement et cause probable

`ReasoningAgent` consomme uniquement les `AgentReport` structurés de la phase 5. Il regroupe des constats connus sous des hypothèses déterministes concernant la pression des ressources, l'accessibilité ou la latence réseau, les alertes réseau historiques, les signaux d'échecs SSH, la source de données de monitoring et la disponibilité d'un serveur. Chaque élément de preuve renvoie à l'agent, au code du constat, à sa source, son champ et sa valeur. Les constats informatifs peuvent être présentés comme contre-indications ; les rapports `no_data` et `error`, ainsi que leurs limites, alimentent `data_gaps`.

La réponse de `POST /api/v1/incidents/diagnose` contient maintenant `reasoning` avec un état (`analyzed` ou `insufficient_data`), un résumé, des hypothèses, des preuves, des limites, un niveau de confiance qualitatif (`low` ou `moderate`) expliqué, et des vérifications diagnostiques proposées. Les alertes seules ne dépassent pas une confiance faible. Les mesures hôte et les sondes réseau directement observées peuvent soutenir une confiance modérée dans le signal observé, mais la réponse précise que la causalité reste à établir sans corrélation temporelle et vérification indépendante. Aucune hypothèse ne confirme une cause racine.

Les hypothèses non reconnues par les règles restent non classées et ne sont pas transformées en cause. Si aucun constat pertinent n'est disponible, le statut devient `insufficient_data` et aucune hypothèse n'est émise. Les prochaines étapes sont des contrôles diagnostiques uniquement : aucun plan d'action, shell, remédiation, ou statut de résolution n'est produit. Le raisonnement ne dispose pas d'historique persistant et n'effectue pas de recherche de cas similaires ; la mémoire des incidents reste une phase ultérieure.
