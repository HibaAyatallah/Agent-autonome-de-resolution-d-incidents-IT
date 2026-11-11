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

Le dataset est disponible sur [Mendeley Data](https://data.mendeley.com/datasets/md7x42rcbm/1). Il regroupe les résultats de **311 tests** réalisés sur une plateforme de surveillance de serveurs intégrant l'intelligence artificielle pour détecter et analyser des incidents.

Les données comprennent des métriques liées à l'utilisation du processeur, de la mémoire et du stockage, des journaux de services, ainsi que des informations sur les alertes et leur temps de réponse. Le dataset inclut également l'analyse des journaux effectuée par le modèle GPT utilisé dans la plateforme.

### Pourquoi ce dataset ?

- **Taille adaptée à un prototype :** les 311 tests sont plus faciles à explorer et à traiter qu'un très grand corpus de télémétrie.
- **Données liées aux incidents :** les métriques et les journaux permettent d'étudier la détection et l'analyse de problèmes système.
- **Lien avec l'architecture du projet :** ces données peuvent alimenter les agents Système et Logs, puis aider l'agent de raisonnement à établir un diagnostic.
- **Évaluation du traitement des alertes :** les temps de réponse permettent d'étudier la rapidité de la prise en charge.

Ce dataset constitue un point de départ pour le prototype. Il ne couvre pas à lui seul toutes les fonctions prévues, notamment le diagnostic réseau, l'exécution de corrections et la vérification après intervention. Ces aspects pourront être ajoutés dans un environnement de test contrôlé.
