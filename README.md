# ZayssScanner

Scanner de backdoors pour serveurs FiveM.  
Détection multi-signatures (Cipher, Blum, ...), analyse d'obfuscation avec scoring, monitoring en temps réel avec alertes Discord.

> [!WARNING]
> **Outil d'audit, non un antivirus infaillible.**  
> Des faux positifs sont possibles — vérifiez toujours manuellement les détections. Aucun scanner ne garantit une couverture totale face aux variantes inconnues.

---

## Sommaire

- [Contexte](#contexte)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Détections](#détections)
- [Niveaux de menace](#niveaux-de-menace)
- [Recommandations](#recommandations)
- [Support](#support)
- [Statistiques](#statistiques)
- [Licence](#licence)

---

## Contexte

Depuis l'explosion des ressources **unlock** et **fxap**, l'écosystème FiveM est devenu un terrain fertile pour les backdoors. Des scripts infectés circulent massivement à travers des ressources "unlockées", revendues ou leakées.

Conséquences observées sur des milliers de serveurs :

| Vecteur | Impact |
|---|---|
| Exécution de code à distance | Contrôle total du serveur |
| Vol de données | Base de données, tokens, webhooks Discord |
| Injection de scripts | Installation automatique de malwares |
| Sabotage | Destruction de données, bannissements massifs |

ZayssScanner est né d'un besoin critique : disposer d'un outil fiable pour analyser ses ressources avant de les utiliser en production.

---

## Fonctionnalités

| Catégorie | Fonctionnalité |
|---|---|
| **Signatures** | Cipher, Blum et variantes personnalisées |
| **Obfuscation** | XOR, Unicode, Base64, fromCharCode, eval() |
| **Scoring** | Niveau de menace gradué (Low → CRITICAL) |
| **Couverture** | Server scripts, client scripts, UI pages, HTML, JS |
| **Automatisation** | Auto-scan à intervalle configurable |
| **Whitelist** | Exclusion de ressources de confiance |
| **Logs** | Historique complet dans `scan_logs/` |

---

## Installation

### Git clone

```bash
cd resources
git clone https://github.com/zayss212/Zayss-Scanner-AntiBackdoorFiveM.git [zayss_scanner]
```

### Téléchargement manuel

1. Téléchargez la [dernière release](https://github.com/zayss212/Zayss-Scanner-AntiBackdoorFiveM)
2. Extrayez dans `resources/[zayss_scanner]`
3. Renommez le dossier en `zayss_scanner`

### server.cfg

```
ensure zayss_scanner
```

> [!WARNING]
> Placez cette ligne **après** toutes vos autres ressources.

---

## Configuration

Éditez `config.lua` :

```lua
ZayssScanner = {}

-- Sécurité
ZayssScanner.StopServer = false  -- Arrête le serveur si backdoor détectée

-- Whitelist
ZayssScanner.IgnoreResources = {
    -- Ajoutez vos ressources de confiance ici
}

-- Options de scan
ZayssScanner.ScanOptions = {
    ScanServerScripts = true,
    ScanClientScripts = true,
    ScanUIPages = true,
    ScanHTMLFiles = true,
    ScanJSFiles = true,
    DeepScan = true
}

-- Auto-scan
ZayssScanner.AutoScan = {
    Enabled = false,
    Interval = 3600000,  -- 1 heure par défaut
}

-- Détection avancée
ZayssScanner.AdvancedDetection = {
    DetectObfuscation = true,
    DetectXOREncryption = true,
    DetectBase64 = true,
    DetectRemoteExecution = true,
    DetectEval = true,
    DetectSuspiciousAPIs = true,
    MinObfuscationScore = 30  -- Score minimum pour alerte
}

return ZayssScanner
```

---

## Utilisation

### Commande

```
scan-backdoor
```

Lance un scan complet de toutes les ressources actives.

### Exemple de sortie

```
[RESSOURCE INFECTÉE DÉTECTÉE] - esx_doorlock
  └─ Fichier: server/main.lua
  └─ Type: [[CIPHER BACKDOOR]]
  └─ Niveau de menace: CRITICAL (Score: 75)

========================================
Total Scanné: 156
Potentiellement infectés: 3
Durée du scan: 2.45s
========================================
```

### Procédure après scan

1. Lancer le serveur et exécuter `scan-backdoor`
2. Arrêter le serveur — supprimer les fichiers détectés (**vérifier manuellement avant toute suppression**)
3. Vider le cache du serveur et supprimer dans `citizen/system_resources` les ressources suspectes (souvent nommées `sys`, `mod`, etc.)
4. Relancer le serveur et refaire un scan pour confirmer

---

## Détections

### Signatures connues

| Famille | Indicateurs |
|---|---|
| **Cipher** | cipher-panel, cfx.re, eszjqvpjhiou, helperServer |
| **Ketamin** | ketamin.cc |
| **Custom** | Patterns personnalisés configurables |

### Techniques d'obfuscation

| Technique | Pattern | Score |
|---|---|---|
| XOR Encryption | `charCodeAt(0)^` | +25 pts |
| fromCharCode | Encodage de caractères | +15 pts |
| Unicode sequences | `\uXXXX` massifs | +20 pts |
| Base64 | `atob()` | +15 pts |
| Remote execution | HTTP + eval | +30 pts |
| eval() | Exécution dynamique | +10 pts |

---

## Niveaux de menace

| Niveau | Score | Interprétation |
|---|---|---|
| **Low** | 0 – 15 | Suspect mais potentiellement légitime |
| **Medium** | 16 – 30 | Attention requise |
| **High** | 31 – 50 | Très suspect — vérification manuelle obligatoire |
| **CRITICAL** | 51+ | Backdoor quasi-certaine |

---

## Recommandations

- Vérifier manuellement chaque détection avant suppression
- Télécharger les ressources depuis des sources fiables uniquement
- Maintenir le scanner à jour pour couvrir les nouvelles signatures
- Effectuer des backups réguliers avant tout scan en production
- Tester d'abord sur un serveur de développement

> [!NOTE]
> Des faux positifs surviennent sur les ressources légitimement obfusquées. Le score est un indicateur, pas un verdict automatique.

---

## Support

- **GitHub** : [github.com/zayss212/Zayss-Scanner](https://github.com/zayss212/Zayss-Scanner-AntiBackdoorFiveM)
- **Discord** : [discord.gg/MsMw2NQ7Vj](https://discord.gg/MsMw2NQ7Vj)
- **Issues** : [Signaler un bug](https://github.com/zayss212/Zayss-Scanner-AntiBackdoorFiveM/issues)

---

## Statistiques

| Métrique | Valeur |
|---|---|
| Signatures de backdoors | 14+ |
| Techniques d'obfuscation couvertes | 8 |
| Temps de scan (150 ressources) | ~2 – 5 secondes |
| Taux de détection estimé | ~95 % |

---

## Licence

MIT License — Copyright (c) 2025 Zayss
