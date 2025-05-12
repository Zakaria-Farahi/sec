---
title: Windows AD Lab
published: 2025-05-11
description: "Active Directory Lab simulate Vulnerable Machine"
image: "./img/img.jpg"
tags: [Project ,AD, windows]
category: 'Project'
draft: false
---


# **Introduction**

Dans le cadre de projet Administration et Sécurité des systems, nous avons mis en place un environnement Active Directory (AD) représentatif d'un système d'entreprise typique, afin d'en étudier les vulnérabilités courantes et les vecteurs d'attaque exploités par des acteurs malveillants. L'objectif principal était d'illustrer, étape par étape, comment une mauvaise configuration et une gestion laxiste des comptes peuvent mener à une compromission totale du domaine.

Le scénario choisi simule l'escalade de privilèges d'un utilisateur à bas niveau (compte stagiaire) jusqu'à l'obtention des droits de l'administrateur de domaine. Pour ce faire, plusieurs techniques d'attaque ont été mises en œuvre, telles que l'accès SMB anonyme, la récupération de tickets Kerberos via Kerberoasting, l'exploitation des privilèges de réplication (DCSync), et l'utilisation de Pass-the-Hash (PTH).

Ce rapport documente l'ensemble du processus : configuration de l'environnement, déroulement de l'attaque, détection possible de l'activité malveillante, ainsi que les mesures correctives à adopter pour prévenir ce type de compromission.

# Phase de Configuration

## Déploiement du contrôleur de domaine (DC)

Nous allons commencer par promouvoir notre serveur Windows en contrôleur de domaine afin de mettre en place une architecture Active Directory.

![ad](Rapport-media/e909e8742797ea043fcafbb0c7197152b1126369.png)

Nous allons configurer le nom de domaine "SaZcorp.ccn", qui signifie Saad à Zakaria Entreprise.

![ad](Rapport-media/ac10407de2fb15e17f1c5441c5e3256b4cb7c9d2.png)

## Configuration de partage SMB

### **Étape 1 : Activer la liste de partage SMB anonyme**

Afin d'activer le partage SMB anonyme, nous devons modifier certaines valeurs dans le registre Windows.

``` bash
# Autoriser les utilisateurs anonymes à répertorier les partages
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 0 -Type DWord

# Autoriser l'accès anonyme aux canaux nommés (nécessaire pour IPC$)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value "srvsvc" -Type MultiString

# Autoriser l'accès anonyme aux actions (facultatif, mais facilite la cotation)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value "Stagaires" -Type MultiString
```

Résultats de notre modification

![ad](Rapport-media/62ea0ec07e58395759faac3f5ac41db0339330b3.png)

### **Étape 2 : Créer et partager le dossier « Stagaires » avec un accès anonyme**

creation de dossier

``` bash
New-Item -Path "C:\Stagaires" -ItemType Directory
```

partage de dossier

``` bash
New-SmbShare -Name "Stagaires" -Path "C:\Stagaires" -FullAccess "Everyone" -ReadAccess "Anonymous Logon"
```

Nous pouvons constater que le dossier a été correctement partagé.

![ad](Rapport-media/8a7faf51d6619456bce01d7e7edaefdfd35ad380.png)

Nous allons accorder les autorisations de lecture et d'exécution à tout le monde, ainsi qu'au groupe "Anonymous Logon".

``` bash
icacls "C:\Stagaires" /grant "Everyone:(OI)(CI)(RX)"  # Read & Execute
icacls "C:\Stagaires" /grant "Anonymous Logon:(OI)(CI)(RX)"  # Explicit anonymous access
```

Résultats

![ad](Rapport-media/2e952c01457787ae8c2639994bfbd1def38787d7.png)

## Création des comptes (internes, comptes de service, etc.)

### Creation des stagiaires

Cliquez sur "Nouveau" puis sélectionnez "Utilisateur".

![ad](Rapport-media/740ac4d1c49ffffbf7325cdb11161c6942eb802e.png)

remplir les informations de l'utilisateurs

![ad](Rapport-media/2dc1de98f811c51fd38c536aa734082342514e5a.png)

mot de pass j'ai choisi "Summer2025"

![ad](Rapport-media/d1e63963fb14167aa62d6182a6ccf0268157e43b.png)

Résultats

![ad](Rapport-media/3546b88bdf418a689a5e087e2b4492d9dfdc2c8b.png)

### Creation des employés

Pour la création des comptes des autres employés, nous avons choisi de procéder de manière automatisée à l'aide de PowerShell.

``` bash
# Create amira.hr
New-ADUser -SamAccountName "amira.hr" -Name "Amira HR" -AccountPassword (ConvertTo-SecureString "P@sswOrd123" -AsPlainText -Force) -ChangePasswordAtLogon $true

# Create karim.sales
New-ADUser -SamAccountName "karim.sales" -Name "Karim Sales" -AccountPassword (ConvertTo-SecureString "P@sswOrd123" -AsPlainText -Force) -ChangePasswordAtLogon $true

# Create layla.finance
New-ADUser -SamAccountName "layla.finance" -Name "Layla Finance" -AccountPassword (ConvertTo-SecureString "P@sswOrd123" -AsPlainText -Force) -ChangePasswordAtLogon $true

# Create nour.support
New-ADUser -SamAccountName "nour.support" -Name "Nour Support" -AccountPassword (ConvertTo-SecureString "P@sswOrd123" -AsPlainText -Force) -ChangePasswordAtLogon $true
```

Résultats

![ad](Rapport-media/e895e6e71d0629cbeb0a4ea8cbdee5b80eac0e56.png)

Afin de permettre l'accès à distance via la console, nous avons ajouté l'utilisateur Youssef au groupe "Remote Management Users".

![ad](Rapport-media/7250bc31a411409bf60af7e8ace9fe181ab75520.png)

Ici, nous allons simuler une mauvaise utilisation du service où l'utilisateur Youssef se connecte à son compte et tente de modifier son mot de passe. Au lieu de suivre une procédure de changement de mot de passe appropriée, il essaie simplement d'ajouter le caractère "@" à son ancien mot de passe "Summer@2025".
\## Creation de compte admin

Nous allons copier les mêmes propriétés que celles du compte Administrateur.

![ad](Rapport-media/af8b39a9cd86754641a39722a1f8faf4401d68c2.png)

Remplir notre informations

![ad](Rapport-media/9fd598e13609bab6fe823e500e5fcdc0f6e3b766.png)

Résultats

![ad](Rapport-media/cf4196ccc5802063092dd48b688cb449989b9076.png)

### Créer un compte de service

Maintenant, nous allons créer le compte de service et définir un SPN (Service Principal Name).

``` bash
New-ADUser -Name "Service DB" -SamAccountName "svc_db" -UserPrincipalName "svc_db@sazcorp.ccn" -AccountPassword (ConvertTo-SecureString "1qaz@WSX" -AsPlainText -Force) -Enabled $true
setspn -A MSSQLSvc/DC.SaZcorp.ccn:1433 svc_db
```

![ad](Rapport-media/023f3355a87efe7e4bd0d93cd6f2ec0c03b6af95.png)

### Configuration des droits d'accès

La commande `dsacls "DC=SaZcorp,DC=ccn" /G "SAZCORP\svc_db:CA;Replicating Directory Changes" /G "SAZCORP\svc_db:CA;Replicating Directory Changes All"` donne au compte de service `svc_db` dans le domaine `SAZCORP` les droits de :
1. Voir et copier les modifications de l'annuaire.
2. Voir et copier *toutes* les modifications de l'annuaire (plus complet).

``` bash
dsacls "DC=SaZcorp,DC=ccn" /G "SAZCORP\svc_db:CA;Replicating Directory Changes" /G "SAZCORP\svc_db:CA;Replicating Directory Changes All"
```

![ad](Rapport-media/90503044ac49839ed831f08de5c148347518f58b.png)

# Phase d'Exploitation

## Accès SMB anonyme et extraction d'informations sensibles

smbclient est un client Samba doté d'une interface de type FTP. C'est un outil utile pour tester la connectivité à un partage Windows. Il peut être utilisé pour transférer des fichiers ou consulter les noms de partage.
-L utiliser pour voir les partages disponibles
-N pour anonymous accés

``` bash
smbclient -L //DC.SaZcorp.ccn/ -N
smbclient //DC.SaZcorp.ccn/Stagaires -N
```

![Pasted image 20250508104456.png](Rapport-media/78e5aaeae662c9bfd81d68764a28acddb19ebc70.png "wikilink")
Le fichier Notes.txt contient les mots de passe initiaux des stagiaires, qui sont "Summer2025". Comme mentionné précédemment, l'utilisateur Youssef a décidé de simplement ajouter un "@" à ce mot de passe, ce qui simplifie notre tâche d'accès.
\## Connexion à un compte interne via Evil-WinRM

WinRM (Windows Remote Management) est l'implémentation Microsoft du protocole WS-Management. Ce protocole standard basé sur SOAP permet l'interopérabilité entre matériels et systèmes d'exploitation de différents fournisseurs. Microsoft l'a intégré à ses systèmes d'exploitation afin de simplifier la vie des administrateurs système.
-i pour ip
-u utilisateur
-p pour mot de pass

``` bash
evil-winrm -i 10.8.0.2 -u youssef.intern -p Summer@2025
```

![ad](Rapport-media/9f428f6face43712a3313c2e9bd42cce000dae25.png)

## Enumération des comptes avec SPN exposés (Kerberoasting)

Le Kerberoasting est une cyberattaque qui exploite le protocole d'authentification Kerberos. Les pirates volent les tickets de service Kerberos pour découvrir les mots de passe en clair des comptes de service réseau. Ils prennent ensuite le contrôle de ces comptes pour voler des données, diffuser des logiciels malveillants, etc.

La commande GetUserSPNs.py d'Impacket tente de récupérer les noms principaux de service associés aux comptes utilisateurs normaux. Elle renvoie un ticket chiffré avec le mot de passe du compte utilisateur, qui peut ensuite être attaqué hors ligne par force brute.

-dc-ip pour specifié l'IP de domain controlleur

``` bash
# Liste les SPN disponibles pour l'utilisateur youssef.intern@SaZcorp.ccn
impacket-GetUserSPNs SaZcorp.ccn/youssef.intern:Summer@2025 -dc-ip 10.8.0.2

# Requête un ticket Kerberos pour les SPN de l'utilisateur youssef.intern@SaZcorp.ccn
impacket-GetUserSPNs SaZcorp.ccn/youssef.intern:Summer@2025 -dc-ip 10.8.0.2 -request

# Tente un brute-force du hash du ticket Kerberos (TGS-REP) pour récupérer le mot de passe
hashcat -m 13100 svc_hash.txt /usr/share/wordlists/rockyou.txt --force
```

![ad](Rapport-media/1513a471fcf20851b85131c69f6b55ae27142391.png)

cracker le hachage que nous avons trouvé

![ad](Rapport-media/a6c59f48e287daf526a87c65d40b8c6490a9ed58.png)

## Vérification et exploitation des privilèges

SharpHound est le collecteur de données officiel de BloodHound. Développé en C#, il utilise les fonctions natives de l'API Windows et les fonctions d'espace de noms LDAP pour collecter les données des contrôleurs de domaine et des systèmes Windows joints à un domaine.

BloodHound utilise la théorie des graphes pour révéler les relations cachées et souvent involontaires au sein d'un environnement Active Directory.

Nous avons commencé par utiliser SharpHound pour collecter des informations sur le domaine. En exécutant SharpHound, nous obtenons un ensemble de données graphiques qui nous aident à visualiser la structure d'Active Directory et à identifier les vulnérabilités potentielles liées aux permissions et aux relations de confiance.

![ad](Rapport-media/8cd03cf939d568f393daa8f719ba03eeef7ac294.png)

Lancez BloodHound et importez les données collectées par SharpHound.

``` bash
bloodhound
```

![Pasted image 20250508120322.png](Rapport-media/e0b241fe137828a9f264c9f5bcfd21ff65fd0fb7.png "wikilink")
Sélectionnez les données appropriées correspondant à notre cible.
![Pasted image 20250508120343.png](Rapport-media/cf4459e08bb4629f73196bd103441b3f882bc65b.png "wikilink")
![Pasted image 20250508120356.png](Rapport-media/81a58072f391221fe65c0a083dab6538dde50005.png "wikilink")

Recherchez notre service cible dans l'interface de BloodHound.

![ad](Rapport-media/2958853c2f48870a2b31a0398ca81ea9a216ce04.png)

Nous pouvons alors observer que notre compte de service possède une permission DCSync sur le contrôleur de domaine.

![ad](Rapport-media/a5393f6a60f58784279923d5ef270a1c7656fd75.png)

## Récupération du hash de l'administrateur (NTLM) via `secretsdump`

Le fichier secretsdump.py d'Impacket exécute diverses techniques pour extraire les secrets de la machine distante sans exécuter d'agent. Ces techniques incluent la lecture des secrets SAM et LSA dans les registres, l'extraction des hachages NTLM, des identifiants en clair et des clés Kerberos, ainsi que l'extraction du fichier NTDS.dit. La commande suivante tente d'extraire tous les secrets de la machine cible en utilisant les techniques mentionnées précédemment.
![Pasted image 20250508151753.png](Rapport-media/c9aac25889f2f974336f3dcc2b47cc38ea87fa95.png "wikilink")

Après avoir récupéré le hash du compte Administrateur, nous pouvons effectuer une attaque Pass-the-Hash, une technique qui permet de s'authentifier sur un système distant en utilisant le hash NTLM ou Kerberos d'un compte au lieu du mot de passe en clair.

![ad](Rapport-media/a64fcb669b9b5d9312ad535d4704283430ce9ab4.png)

# Détection et Analyse