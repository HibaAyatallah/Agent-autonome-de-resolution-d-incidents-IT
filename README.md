# Agent autonome de résolution d'incidents IT

## 1. Présentation du projet

Ce projet consiste à développer un système intelligent multi-agents capable de détecter, diagnostiquer et résoudre automatiquement des incidents informatiques (IT), avec une intervention humaine minimale.

Le système repose sur plusieurs agents spécialisés qui collaborent pour identifier l'origine d'un incident, proposer une solution, exécuter les actions nécessaires et vérifier le résultat.

## 2. Objectifs du projet

- Détecter automatiquement les incidents informatiques.
- Analyser les logs et les métriques système.
- Identifier la cause probable d'un problème.
- Coordonner plusieurs agents spécialisés.
- Générer un plan de résolution.
- Exécuter automatiquement les actions autorisées.
- Vérifier que l'incident est réellement résolu.
- Conserver une mémoire des incidents précédents.

## 3. Architecture multi-agents

Le système est composé de plusieurs agents :

### 3.1 Agent coordinateur

- Reçoit les incidents provenant des utilisateurs ou du monitoring.
- Coordonne les différents agents spécialisés.
- Centralise les résultats du diagnostic.

### 3.2 Agents spécialisés

**Agent Logs**

- Analyse les fichiers logs.
- Identifie les erreurs et les anomalies.

**Agent Réseau**

- Vérifie la connectivité.
- Analyse les problèmes de latence et de réseau.

**Agent Système**

- Surveille le CPU, la RAM et le disque.
- Détecte les problèmes de performance.

**Agent Sécurité**

- Recherche les comportements suspects.
- Identifie les éventuelles menaces de sécurité.

### 3.3 Agent de raisonnement

- Analyse les informations collectées.
- Recherche des incidents similaires dans la mémoire.
- Identifie la cause probable.
- Génère un plan de résolution.

### 3.4 Agent d'action

- Exécute les actions de correction autorisées.
- Applique le plan de résolution.
- Enregistre les actions effectuées.

### 3.5 Agent de vérification

- Vérifie l'état du système après correction.
- Confirme la résolution de l'incident.
- Relance le diagnostic si nécessaire.

## 4. Exemple de fonctionnement

**Scénario : un serveur devient lent.**

1. Le système détecte une baisse de performance.
2. L'agent coordinateur reçoit l'incident.
3. Les agents spécialisés analysent les logs, le réseau et les ressources système.
4. L'agent de raisonnement identifie une consommation excessive de RAM.
5. Un plan de résolution est généré.
6. L'agent d'action applique une correction autorisée.
7. L'agent de vérification contrôle les performances.
8. L'incident est marqué comme résolu si les résultats sont satisfaisants.

## 5. Architecture générale

```text
Incident
   ↓
Agent coordinateur
   ↓
Agents spécialisés
   ├── Agent Logs
   ├── Agent Réseau
   ├── Agent Système
   └── Agent Sécurité
   ↓
Agent de raisonnement
   ↓
Plan de résolution
   ↓
Agent d'action
   ↓
Agent de vérification
   ↓
Incident résolu ou nouveau diagnostic
```

## 6. Fonctionnalités principales

- Orchestration multi-agents.
- Monitoring en temps réel.
- Analyse intelligente des logs.
- Diagnostic automatisé.
- Mémoire des incidents.
- Génération de plans de résolution.
- Exécution contrôlée des actions.
- Boucle de vérification et de correction.

## 7. Sécurité et garde-fous

- Validation des actions sensibles.
- Autorisations limitées pour chaque agent.
- Journalisation des actions exécutées.
- Possibilité d'intervention humaine.
- Protection contre les actions dangereuses ou répétitives.

## 8. Niveau du projet

Très avancé – système autonome multi-agents avec orchestration intelligente, raisonnement, monitoring et automatisation de la résolution des incidents IT.

## 9. Perspectives d'évolution

- Intégration de modèles LLM.
- Ajout de nouveaux agents spécialisés.
- Tableau de bord de monitoring.
- Amélioration de la mémoire des incidents.
- Apprentissage à partir des incidents historiques.

## 10. Équipe du projet

| Membre | Nom complet |
|---|---|
| Membre A | Hiba Ayatallah |
| Membre B | Manal Wassila |

## 11. Dataset choisi

### Systems monitoring platform for AI incident response

Source : [Mendeley Data](https://data.mendeley.com/datasets/md7x42rcbm/1). L'archive fournie contient `results.xlsx`, avec une feuille principale de **311 lignes et 6 colonnes** (`Datos finales`) et une feuille de synthèse (`Hoja 5`). La feuille principale fournit les temps d'acquittement, de traitement et d'envoi d'analyse, l'heure de création, un type (`log` ou `usage`) et un payload JSON d'alerte.

L'inspection du fichier montre **303 alertes `log` et 8 alertes `usage`**. Les alertes comprennent notamment des échecs d'authentification SSH, des alertes CPU/RAM/réseau et des erreurs ou absences de données de source. Les 311 payloads ont le statut `firing`.

### Pourquoi ce dataset ?

- Il fournit des alertes au format proche d'un événement de monitoring réel, que le projet peut ingérer et classer.
- Il contient des messages et des métadonnées utiles à l'agent Logs et au triage initial par le coordinateur.
- Ses temps de réponse permettent d'étudier les délais d'acquittement et de traitement.
- Son volume réduit convient à la mise au point et à la démonstration du pipeline.

**Limites constatées :** le fichier ne contient pas les mesures brutes de CPU, RAM ou disque, les journaux système complets, une série temporelle de métriques, des traces réseau détaillées, ni des actions de remédiation et leurs résultats de vérification. Les noms des champs de temps n'indiquent pas clairement leur unité dans le classeur. Le prototype traitera donc ce fichier comme un historique d'alertes, et utilisera des mesures système/réseau en direct ou des scénarios simulés pour les autres agents. Aucun résultat de remédiation ne sera déduit de ce dataset.

## 12. Architecture initiale

La proposition d'architecture, les choix technologiques, les limites de données et la structure créée pour le projet sont décrits dans [docs/architecture.md](docs/architecture.md). Le développement fonctionnel suivra les phases du cahier des charges, avec validation avant de commencer la phase suivante.

Le module d'ingestion de la phase 2 est prêt. Après installation de l'environnement décrit dans `docs/architecture.md`, lance `python -m incident_response.dataset` pour régénérer les alertes normalisées et le rapport d'inspection dans `data/processed/`.

Le collecteur de la phase 3 expose `GET /api/v1/monitoring/snapshot` et peut aussi être lancé en continu avec `python -m incident_response.monitoring --interval 5`. Configure les seuils et les cibles TCP autorisées dans `.env` (voir `.env.example`). Pour démarrer l'API : `uvicorn incident_response.main:app --app-dir backend/src --reload`.

Les agents Logs, Système, Réseau et Sécurité de la phase 4 analysent maintenant ces événements et mesures sous forme de rapports structurés. Ils restent indépendants ; leur coordination arrivera en phase 5.

La phase 5 ajoute `POST /api/v1/incidents/diagnose` : le coordinateur distribue le contexte aux quatre agents en parallèle, conserve leur état et leur timeline, puis renvoie catégorie et priorité initiales.

La phase 6 ajoute un raisonnement déterministe sur les rapports structurés. La réponse expose `reasoning.status`, des hypothèses reliées aux preuves des agents, un niveau de confiance motivé, les limites et les prochaines vérifications diagnostiques. Une hypothèse n'est jamais présentée comme une cause confirmée. Les alertes du dataset restent des alertes : elles ne sont pas converties en métriques brutes, journaux complets ou preuves de résolution. Cette phase ne lance aucune remédiation et n'expose aucune commande.

La phase 7 ajoute la mémoire persistante avec SQLite par défaut (`data/incidents.db`) et SQLAlchemy. Chaque diagnostic est enregistré avec ses catégories, sa priorité, ses constats sûrs et ses hypothèses ; les dossiers historiques similaires sont ajoutés comme contexte, sans augmenter la confiance ni confirmer une résolution. Les champs de cause confirmée, d'action, de vérification et de statut final restent vides jusqu'à ce que les phases correspondantes fournissent ces résultats. Les adresses IP, e-mails et chaînes de type secret sont masqués dans les descriptions stockées. PostgreSQL peut être configuré avec `DATABASE_URL` et l'extra `.[postgres]`.

La consultation de l'historique est disponible sur `GET /api/v1/incidents/history` (filtres `q`, `priority`, `category`, pagination `limit`/`offset`) et dans le tableau de bord servi à `/dashboard`. L'interface affiche les diagnostics mémorisés, leurs constats et hypothèses, sans présenter les alertes du dataset comme des incidents résolus.
