# projet-django — Scanner de sécurité web

Application Django qui lance trois outils de reconnaissance et d'audit depuis le navigateur, enregistre les résultats en base et les affiche dans une page HTML :

| Outil | Ce qu'il fait | Entrée |
|-------|---------------|--------|
| **Nmap** | Liste les ports ouverts d'une machine et les services associés | Adresse IP |
| **WhatWeb** | Identifie les technologies d'un site (serveur, CMS, frameworks, versions) | URL |
| **OWASP ZAP** | Explore le site (spider) puis lance un scan actif de vulnérabilités | URL |

> ⚠️ **Usage légal uniquement.** Ne scannez que des machines et des sites qui vous appartiennent ou pour lesquels vous avez une autorisation écrite.

---

## Fonctionnement

1. L'utilisateur appelle un endpoint avec une IP ou une URL en paramètre.
2. L'entrée est validée (format de l'IP, format de l'URL, URL joignable en HTTP).
3. **Si un scan existe déjà en base** pour cette cible, il est renvoyé directement, sans relancer l'outil.
4. Sinon, l'outil est exécuté (`subprocess`), sa sortie est analysée ([nmapapp/parsers.py](nmapapp/parsers.py)), puis enregistrée dans la base SQLite.
5. Le résultat s'affiche dans un template HTML.

## Stack technique

- Python 3.13
- Django 5.1
- Django REST Framework (serializers)
- `requests`
- SQLite

## Structure du projet

```
projet-django/
├── manage.py
├── nmaptest/              # Configuration du projet Django
│   ├── settings.py
│   └── urls.py
└── nmapapp/               # Application principale
    ├── models.py          # ScanNmap, ScanWhatweb, ScanZap
    ├── views.py           # Une vue par outil de scan
    ├── parsers.py         # Analyse de la sortie de chaque outil
    ├── serializers.py     # Serializers DRF
    ├── urls.py            # Routes des scans
    └── templates/         # Pages de résultats HTML
```

---

## Prérequis

Le projet a été développé sous **Windows** : WhatWeb est lancé via WSL et ZAP est appelé via PowerShell.

- **Python 3.11+**
- **Nmap**, installé et disponible dans le `PATH` ([nmap.org/download](https://nmap.org/download))
- **WSL avec une distribution `Ubuntu`** contenant WhatWeb :
  ```bash
  sudo apt install whatweb
  ```
- **OWASP ZAP** lancé en mode démon sur le port `8090`, avec l'API activée :
  ```bash
  zap.bat -daemon -port 8090 -config api.key=VOTRE_CLE_API
  ```

## Installation

```bash
# 1. Cloner le dépôt
git clone https://github.com/assadakh/projet-django.git
cd projet-django

# 2. Créer et activer un environnement virtuel
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

# 3. Installer les dépendances
python -m pip install django djangorestframework requests

# 4. Créer la base de données
python manage.py migrate

# 5. Lancer le serveur
python manage.py runserver
```

L'application est alors accessible sur `http://127.0.0.1:8000/`.

> **Erreur « l'exécution de scripts est désactivée sur ce système » sous PowerShell ?**
> Autorisez les scripts locaux pour votre utilisateur, puis relancez l'activation :
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### Configuration de ZAP

La clé d'API ZAP est définie dans [nmapapp/views.py](nmapapp/views.py), dans la classe `ZapScanAPIView`. Remplacez-la par la clé avec laquelle vous avez démarré ZAP.

---

## Utilisation

Les scans se lancent avec une requête `GET` et un paramètre dans l'URL :

| Scan | Endpoint | Exemple |
|------|----------|---------|
| Nmap | `/nmapscan/?ip=<IP>` | `http://127.0.0.1:8000/nmapscan/?ip=192.168.1.1` |
| WhatWeb | `/whatwebscan/?url=<URL>` | `http://127.0.0.1:8000/whatwebscan/?url=https://example.com` |
| ZAP | `/zapscan/?url=<URL>` | `http://127.0.0.1:8000/zapscan/?url=http://testphp.vulnweb.com` |

Données renvoyées :

- **Nmap** : port, état (`open`, `filtered`…), service
- **WhatWeb** : technologies détectées au format `Techno[version]`
- **ZAP** : nom de l'alerte, niveau de risque, niveau de confiance, description, solution recommandée, référence

> Le scan ZAP dure environ 20 secondes : 5 s de spider puis 15 s de scan actif avant la récupération des alertes.

## Modèles de données

| Modèle | Champs |
|--------|--------|
| `ScanNmap` | `ip`, `port`, `state`, `service`, `date_scan` |
| `ScanWhatweb` | `url`, `result`, `date_scan` |
| `ScanZap` | `url`, `alert`, `name`, `risk`, `confidence`, `description`, `solution`, `reference`, `date_scan` |

## Pistes d'amélioration

- Ajouter un fichier `requirements.txt`
- Déplacer la clé d'API ZAP et la `SECRET_KEY` dans des variables d'environnement (`.env`)
- Permettre de relancer un scan même si un résultat existe déjà en base
- Interroger l'API ZAP pour connaître l'avancement du scan au lieu d'attendre un délai fixe
- Rendre le projet multiplateforme (appeler WhatWeb et ZAP sans WSL ni PowerShell)
- Ajouter des tests unitaires pour les parsers

## Auteur

**assadakh** — [github.com/assadakh](https://github.com/assadakh)
