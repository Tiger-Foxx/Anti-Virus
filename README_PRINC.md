# Foxy Security - Documentation du Code

## 1. Introduction

Foxy Security (Foxy - Python AntiVirus System) est une application antivirus développée en Python. Elle utilise PyQt5 pour son interface graphique utilisateur et `ctypes` pour interagir directement avec l'API Windows afin d'assurer la surveillance et le contrôle système de bas niveau.

Ce document fournit une explication détaillée du code Python, couvrant sa structure, ses fonctionnalités principales (analyse, protection en temps réel, outils système), les détails d'implémentation, la gestion de la configuration et les éléments de l'interface utilisateur. L'objectif est de comprendre comment les différents composants fonctionnent ensemble pour fournir des fonctionnalités de sécurité.

**Technologies Clés :**

*   **Python 3 :** Langage de programmation principal.
*   **PyQt5 :** Framework pour l'interface graphique utilisateur (GUI).
*   **ctypes :** Bibliothèque Python pour appeler des fonctions dans des DLLs/bibliothèques partagées (utilisée largement pour les appels à l'API Windows).
*   **Moteurs d'Analyse Personnalisés :** `Foxy_Engine` (contenant `DLScan` pour les modèles d'apprentissage profond et `YRScan` pour les règles YARA - implémentations supposées externes à ce fichier).
*   **Threading :** Utilisé pour les tâches d'arrière-plan comme la surveillance en temps réel et l'analyse afin de maintenir la réactivité de l'interface utilisateur.
*   **JSON :** Pour stocker les paramètres de configuration.

## 2. Structure Principale et Initialisation

L'application est principalement construite autour de la classe `MainWindow_Controller`, qui hérite de `QMainWindow` (PyQt5).

### 2.1. Classe Principale : `MainWindow_Controller`

*   Agit comme le hub central de l'application.
*   Gère l'interface utilisateur, l'état, la configuration et les threads de protection en arrière-plan.
*   Gère les interactions utilisateur et coordonne les différents modules.

### 2.2. Séquence d'Initialisation (`__init__`, `init_config_Foxy`)

L'application suit un processus d'initialisation structuré orchestré par `init_config_Foxy`, qui appelle plusieurs méthodes spécifiques `init_config_*` dans l'ordre :

1.  **`init_config_vars` :** Initialise les variables d'état internes (versions, indicateurs comme `first_startup`, compteurs d'analyse, listes, structure de configuration par défaut `default_json`).
2.  **`init_config_path` :** Définit les chemins essentiels du système de fichiers (répertoire de configuration, chemin de l'exécutable, chemins des moteurs, chemin du pilote).
3.  **`init_config_read` :** Lit la configuration depuis `C:/ProgramData/Foxy/Foxy.json`. Si le fichier ou le répertoire n'existe pas, il les crée et écrit les paramètres `default_json`. S'assure que toutes les clés de configuration attendues sont présentes.
4.  **`init_config_wdll` :** Charge les DLL Windows nécessaires en utilisant `ctypes.WinDLL`. Cela fournit l'accès aux fonctions de l'API Windows requises pour les fonctionnalités principales.
    *   `ntdll.dll` : Fonctions natives de l'API (ex: `NtSuspendProcess`, `NtResumeProcess`).
    *   `psapi.dll` : API d'état des processus (ex: `EnumProcesses`, `GetProcessImageFileNameW`).
    *   `user32.dll` : Fonctions d'interface utilisateur (ex: gestion des fenêtres, messages, `SystemParametersInfoW`).
    *   `kernel32.dll` : Fonctions système principales (ex: gestion des processus/threads, E/S de fichiers, `ReadDirectoryChangesW`, `OpenProcess`, `TerminateProcess`, `QueryDosDeviceW`).
    *   `advapi32.dll` : Services API avancés (ex: fonctions du Registre comme `RegOpenKeyExW`, `RegSetValueExW`, `RegDeleteValueW`).
    *   `iphlpapi.dll` : API d'aide IP (ex: `GetExtendedTcpTable` pour les connexions réseau).
5.  **`init_config_boot` :** Tente de lire le Master Boot Record (MBR) depuis `\\.\PhysicalDrive0`. Stocke les 512 premiers octets dans `self.mbr_value` si la signature (`\x55\xAA`) est valide. Nécessite les privilèges Administrateur. Cette valeur stockée est utilisée pour la protection du démarrage.
6.  **`init_config_list` :** Remplit les ensembles initiaux de processus existants (`get_process_list`) et de connexions réseau (`get_connections_list`) pour établir une base de référence pour la surveillance en temps réel.
7.  **`init_config_data` :** Initialise les moteurs d'analyse (`DLScan`, `YRScan`) en chargeant les modèles depuis `Engine/Model` et les règles depuis `Engine/Rules`.
8.  **`init_config_icon` :** Crée et affiche l'icône de la zone de notification système (`QSystemTrayIcon`), connectant son activation à l'affichage de la fenêtre principale.
9.  **`init_config_qtui` :** Configure l'interface utilisateur en utilisant la classe `Ui_MainWindow` (générée depuis Qt Designer - `Foxy_Interface.py`). Elle configure les widgets, les ombres, la visibilité initiale, et connecte les signaux (clics de bouton, etc.) aux slots (méthodes de gestion).
10. **`init_config_color` :** Définit les différents thèmes de couleur (Blanc, Rouge, Vert, etc.) incluant les styles de boutons et les couleurs d'arrière-plan dans le dictionnaire `self.config_theme`.
11. **`init_config_conn` :** Connecte les signaux des éléments UI (comme `clicked`) à leurs méthodes correspondantes (slots) dans la classe `MainWindow_Controller` (ex: `self.ui.Close_Button.clicked.connect(self.close)`).
12. **`init_config_lang` :** Définit l'état initial des boutons radio de sélection de langue basé sur le fichier de configuration. Appelle `init_change_text` pour appliquer le texte statique en anglais à tous les éléments de l'interface utilisateur.
13. **`init_config_func` :** Démarre les fonctions principales d'arrière-plan et les threads de protection basé sur la configuration chargée (ex: démarre `protect_proc_thread` si `proc_protect` vaut 1). Initialise également l'interface utilisateur de l'état du pilote, le blocage des fenêtres et le thread de garbage collection.
14. **`init_config_done` :** Marque la fin de la configuration initiale (`self.first_startup = 0`) et affiche la fenêtre principale (sauf si démarré caché via des arguments de ligne de commande).
15. **`init_config_theme` :** Définit les boutons radio de l'interface utilisateur pour le thème basé sur la configuration et appelle `init_change_color` pour appliquer les styles du thème sélectionné.

### 2.3. Interaction avec l'API Windows (`ctypes`)

`ctypes` est fondamental pour les fonctionnalités nécessitant un accès système de bas niveau :

*   **Gestion des Processus :** `OpenProcess`, `TerminateProcess`, `EnumProcesses`, `GetProcessImageFileNameW`, `QueryFullProcessImageNameW`, `NtSuspendProcess`, `NtResumeProcess`.
*   **Gestion des Fenêtres :** `GetForegroundWindow`, `GetWindowTextLengthW`, `GetWindowTextW`, `GetClassNameW`, `EnumWindows`, `IsWindow`, `SendMessageW`, `PostMessageW`.
*   **Accès au Registre :** `RegOpenKeyExW`, `RegCloseKey`, `RegQueryInfoKeyW`, `RegEnumKeyExW`, `RegSetValueExW`, `RegDeleteValueW`, `RegDeleteKeyW`, `RegCreateKeyExW`.
*   **Réseautage :** `GetExtendedTcpTable` (pour obtenir les connexions avec les PIDs propriétaires).
*   **Surveillance du Système de Fichiers :** `CreateFileW` (pour obtenir un handle sur le lecteur), `ReadDirectoryChangesW`.
*   **Accès Disque Brut :** `CreateFileW` (sur `\\.\PhysicalDrive0`) pour l'accès au MBR.
*   **Paramètres du Bureau :** `SystemParametersInfoW` (pour le fond d'écran).
*   **Verrouillage de Fichiers :** `msvcrt.locking` (via un handle `os.open`).

Les structures comme `PROCESSENTRY32`, `MIB_TCPROW_OWNER_PID`, `FILE_NOTIFY_INFORMATION` sont définies en utilisant `ctypes.Structure` pour interpréter les données retournées par les appels API.

### 2.4. Gestion de la Configuration (`Foxy.json`)

*   **Emplacement :** `C:/ProgramData/Foxy/Foxy.json` (nécessite les permissions appropriées).
*   **Format :** JSON.
*   **Chargement :** `init_config_read` utilise `json.load` et gère les fichiers/clés manquants en utilisant `default_json`.
*   **Sauvegarde :** `init_config_write` utilise `json.dumps` pour sauvegarder l'état actuel de `self.config_json`. Les paramètres sont sauvegardés lorsqu'ils sont basculés, les thèmes changés, les listes modifiées, ou à la sortie.
*   **Réinitialisation :** `reset_options` rétablit `self.config_json` à `default_json` et sauvegarde.

## 3. Fonctionnalités Principales & Implémentation

### 3.1. Analyse Antivirus

*   **Objectif :** Détecter les menaces dans les fichiers, répertoires ou disques entiers en utilisant les moteurs d'analyse configurés.
*   **Interface Utilisateur :** Gérée dans `Virus_Scan_widget`. Les boutons déclenchent les analyses, `Virus_Scan_output` (QListWidget) affiche les résultats, `Virus_Scan_Solve_Button` supprime les menaces sélectionnées.
*   **Implémentation :**
    *   **Déclencheurs d'Analyse :** `file_scan`, `path_scan`, `disk_scan` gèrent la sélection de fichiers/répertoires et initient le processus d'analyse.
    *   **Flux d'Analyse :**
        1.  `init_scan` : Réinitialise les variables d'état, nettoie l'UI, masque/affiche les boutons.
        2.  `_run_scan_thread` : Démarre la fonction d'analyse appropriée (`scan_single_file`, `traverse_path`, `scan_all_drives`) dans un thread d'arrière-plan (`threading.Thread`). Utilise un `QTimer` (`scan_check_timer`) pour surveiller la fin du thread sans bloquer l'UI.
        3.  `traverse_path` (pour analyses de chemin/disque) : Parcourt récursivement les répertoires en utilisant `os.scandir`. Vérifie l'indicateur `self.scan_file` pour permettre l'interruption. Ignore les chemins sur liste blanche. Appelle `start_scan` pour chaque fichier. Met à jour l'UI (`Virus_Scan_text`) périodiquement.
        4.  `start_scan` : La logique d'analyse principale. Appelle `self.model.dl_scan` et, si `extend_mode` est activé, `self.rules.yr_scan`. Retourne une chaîne de résultat (ex: "Malware.DL85", "RuleName.YR_Match") ou `False`. Le paramètre de sensibilité (`sensitivity`) affecte le seuil de rapport des résultats DL.
        5.  `write_scan` : Si `start_scan` trouve une menace, cette fonction (appelée via `QMetaObject.invokeMethod` pour la sécurité inter-threads) ajoute le résultat à `virus_list_ui` et au QListWidget `Virus_Scan_output`. Elle tente également de verrouiller le fichier détecté (`lock_file`).
        6.  `answer_scan` : Appelé après la fin du thread d'analyse. Met à jour les titres de l'interface utilisateur (`Virus_Scan_title`, `Virus_Scan_text`) avec un résumé (menaces trouvées, temps pris, fichiers analysés). Affiche `Virus_Scan_Solve_Button` si des menaces ont été trouvées. Envoie une notification (`send_notify`).
    *   **Interruption :** `virus_scan_break` met `self.scan_file` à `False`, ce que les boucles d'analyse vérifient. Met à jour l'UI pour indiquer "Analyse Arrêtée".
    *   **Gestion des Menaces :**
        *   `lock_file` : Utilise `msvcrt.locking` sur un handle de fichier obtenu via `os.open` pour empêcher le fichier détecté d'être facilement exécuté ou modifié pendant qu'il est listé. Les handles sont stockés dans `self.virus_lock`.
        *   `virus_solve` : Itère sur les éléments cochés dans `Virus_Scan_output`. Pour chaque élément sélectionné, il déverrouille le fichier (`lock_file(..., False)`), tente `os.remove`, et met à jour la liste de l'UI.

### 3.2. Protection en Temps Réel

*   **Objectif :** Surveiller l'activité du système en arrière-plan et intervenir lorsqu'un comportement suspect ou malveillant est détecté. S'exécute dans des threads séparés.
*   **Modules :**

    *   **Protection des Processus (`protect_proc_thread`)**
        *   **Surveillance :** Récupère périodiquement la liste des processus actuels (`get_process_list` via `EnumProcesses`). La compare avec la liste précédente (`self.exist_process`) pour trouver les nouveaux PIDs.
        *   **Gestion des Nouveaux Processus (`handle_new_process`) :**
            1.  Ouvre le nouveau processus (`OpenProcess` avec les droits nécessaires).
            2.  Récupère le chemin de l'exécutable (`get_process_file`).
            3.  Vérifie si le chemin est sur liste blanche (`check_whitelist`).
            4.  S'il n'est pas sur liste blanche, suspend le processus (`lock_process` via `NtSuspendProcess`).
            5.  Analyse l'exécutable (`start_scan`).
            6.  Si malveillant : Termine le processus (`kill_process` via `TerminateProcess`). Envoie une notification.
            7.  Si propre : Reprend le processus (`lock_process` via `NtResumeProcess`). Stocke le PID et le chemin dans `self.track_proc` pour une utilisation potentielle par d'autres modules de protection.
        *   **Suivi (`self.track_proc`) :** Stocke `(pid, path)` du processus le plus récemment analysé, non sur liste blanche et propre. Cela permet de lier une activité suspecte ultérieure (modifications de fichiers, écritures MBR) à un processus source potentiel. *Limitation : Ne suit que le *dernier* processus de ce type.*

    *   **Protection des Fichiers (`protect_file_thread`)**
        *   **Surveillance :** Utilise `ReadDirectoryChangesW` sur un handle vers la racine du lecteur C:\ (`CreateFileW` avec `FILE_FLAG_BACKUP_SEMANTICS`) pour surveiller les renommages de fichiers/répertoires, les écritures et les changements de taille dans toute l'arborescence.
        *   **Gestion des Changements :**
            1.  Analyse les structures `FILE_NOTIFY_INFORMATION` depuis le buffer retourné par `ReadDirectoryChangesW`.
            2.  Extrait l'action (Créé, Modifié, Renommé) et le chemin du fichier.
            3.  **Heuristique Antirançongiciel :** Si le changement (modification/renommage) implique des types de fichiers sensibles (`file_types`) dans des zones sensibles (hors Temp/AppData) et qu'un processus est suivi (`self.track_proc`), incrémente `self.ransom_counts`. Si le compteur dépasse un seuil (ex: 5), il tue le processus suivi (`kill_process`).
            4.  **Analyse à la Création/Modification :** Si un fichier est ajouté ou modifié en dehors des dossiers système/programmes et n'est pas sur liste blanche, il est analysé (`start_scan`). S'il est trouvé malveillant, il est supprimé (`os.remove`), une notification est envoyée, et le processus suivi responsable (le cas échéant) peut être tué.
        *   *Limitation :* Actuellement codé en dur pour ne surveiller que le lecteur C:\.

    *   **Protection Système (Démarrage & Registre)**
        *   **Protection du Démarrage (`protect_boot_thread`) :**
            *   Nécessite la lecture initiale du MBR (`self.mbr_value`).
            *   Relit périodiquement le MBR en utilisant l'accès disque brut (`open(r"\\.\PhysicalDrive0", "r+b")`).
            *   Vérifie la signature de démarrage (`\x55\xAA`).
            *   Compare le MBR actuel avec la valeur stockée `self.mbr_value`.
            *   Si modifié ou signature invalide : Tue le processus suivi (`self.track_proc`) s'il en existe un, en supposant qu'il était responsable. Demande à l'utilisateur (`question_event`) s'il faut restaurer le MBR d'origine en réécrivant `self.mbr_value` sur le disque (opération risquée).
        *   **Protection du Registre (`protect_reg_thread`) :**
            *   Périodiquement (ex: toutes les 5 minutes) appelle les fonctions de réparation (`repair_system_image`, `repair_system_restrict`, `repair_system_file_type`, `repair_system_file_icon`).
            *   Ces fonctions fournissent implicitement une protection car elles tentent d'annuler les modifications malveillantes. Si un processus suivi (`self.track_proc`) est actif *pendant* qu'une fonction de réparation tente de supprimer une clé/valeur de registre malveillante définie par ce processus, les assistants `delete_registry_*` appellent `kill_process`.

    *   **Protection Réseau (`protect_net_thread`)**
        *   **Surveillance :** Récupère périodiquement la liste des connexions TCP et leurs PIDs propriétaires (`get_connections_list` via `GetExtendedTcpTable`). Compare avec la liste précédente (`self.exist_connections`).
        *   **Gestion des Nouvelles Connexions (`handle_new_connection`) :**
            1.  Se concentre sur les connexions nouvellement *établies* (état 5).
            2.  Ignore les connexions localhost (loopback).
            3.  Ouvre le processus propriétaire (`OpenProcess`).
            4.  Récupère le chemin du processus (`get_process_file`). Vérifie la liste blanche.
            5.  Vérifie si l'adresse IP distante est dans une liste de blocage (ex: `self.rules.network`).
            6.  Si connexion à une IP bloquée : Termine le processus (`kill_process`). Envoie une notification.

    *   **Protection par Pilote (`protect_drv_init`)**
        *   **Objectif :** Utilise un pilote noyau (`Foxy_Driver`) pour une auto-protection ou des hooks système potentiellement plus forts (les détails d'implémentation du pilote lui-même sont externes).
        *   **Gestion :** Interagit avec le Gestionnaire de Contrôle des Services Windows via l'outil en ligne de commande `sc` (`Popen`).
        *   **Opérations :** Utilise `sc query` pour vérifier l'état, `sc start` pour démarrer, `sc stop` pour arrêter. Utilise `Install_Driver.bat` (contenant probablement `sc create` et potentiellement des commandes de chargement de pilote) et `Uninstall_Driver.bat` (contenant probablement `sc stop`, `sc delete`) situés dans `Driver/Protect`.
        *   **Interaction Utilisateur :** Demande à l'utilisateur (`question_event`) avant l'installation (en raison des risques de compatibilité) ou optionnellement la désinstallation après l'arrêt. Nécessite les privilèges Administrateur et souvent des redémarrages. L'état du bouton reflète l'état interrogé du service ("Activé", "Désactivé", "Indisponible", "Erreur").

    *   **Liste Blanche (`check_whitelist`)**
        *   Utilisé par les fonctions d'analyse et les modules de protection en temps réel.
        *   Prend un chemin de fichier ou de répertoire.
        *   Compare le chemin normalisé avec chaque entrée dans `config_json["white_lists"]`.
        *   Retourne `True` si le chemin correspond exactement ou est à l'intérieur d'un répertoire sur liste blanche.

### 3.3. Outils Système

*   **Objectif :** Fournir des utilitaires pour la gestion et la réparation du système accessibles depuis la section "Outils".
*   **Modules :**

    *   **Gestionnaire de Processus (`process_list`, `process_list_menu`)**
        *   **Interface Utilisateur :** `Process_widget` contenant un `QListView` (`Process_list`).
        *   **Fonctionnalité :** `process_list` (appelé par `QTimer`) met périodiquement à jour la vue de liste en appelant `get_process_list` et `get_process_file`. `process_list_menu` fournit un menu contextuel par clic droit pour terminer (`kill_process`) le processus sélectionné.
    *   **Réparation Système (`repair_system`, `repair_system_*`)**
        *   **Interface Utilisateur :** Déclenché par un bouton dans `Tools_widget`.
        *   **Fonctionnalité :** Appelle des fonctions de réparation individuelles :
            *   `repair_system_restrict` : Supprime les valeurs de restriction courantes des clés de stratégie du registre.
            *   `repair_system_image` : Supprime les valeurs 'Debugger' des clés de registre IFEO (détournements potentiels).
            *   `repair_system_file_icon` : Réinitialise l'icône par défaut des `.exe` dans le registre.
            *   `repair_system_file_type` : Réinitialise l'association de fichier `.exe` et la commande d'ouverture dans le registre.
            *   `repair_system_wallpaper` : Réinitialise le fond d'écran en utilisant le registre et `SystemParametersInfoW`.
        *   Utilise les fonctions d'aide au registre (`set_registry_value`, `delete_registry_value`, etc.).
    *   **Réparation Réseau (`repair_network`)**
        *   **Interface Utilisateur :** Déclenché par un bouton.
        *   **Fonctionnalité :** Exécute `netsh winsock reset` via `Popen`. Demande un redémarrage.
    *   **Nettoyage Système (`clean_system`)**
        *   **Interface Utilisateur :** Déclenché par un bouton.
        *   **Fonctionnalité :** Supprime le contenu des dossiers Temp Windows et Temp Utilisateur récursivement (`traverse_and_delete`). Utilise optionnellement `winshell` (si installé) pour vider la Corbeille. Rapporte la taille supprimée.
    *   **Bloqueur de Popups (`add_software_window`, `remove_software_window`, `block_software_window`)**
        *   **Interface Utilisateur :** Boutons Ajouter/Supprimer dans `Tools_widget`.
        *   **Fonctionnalité :**
            *   `add/remove_software_window` : Met en pause le blocage, invite l'utilisateur à cliquer sur une fenêtre cible. Récupère les informations de la fenêtre (`get_window_info` via `GetWindowTextW`, `GetClassNameW`). Demande confirmation. Ajoute/supprime l'entrée de dictionnaire `{titre: nom_classe}` à/de `config_json["block_lists"]`. Redémarre le thread de blocage.
            *   `block_software_window` (Thread) : Énumère périodiquement les fenêtres de premier niveau (`EnumWindows`). Récupère les informations pour chacune. Si les informations correspondent à une entrée dans `block_lists` (et ne sont pas dans `pass_windows`), envoie des messages de fermeture (`WM_CLOSE`, `WM_SYSCOMMAND SC_CLOSE`) via `PostMessageW`.

### 3.4. Paramètres et Configuration

*   **Interface Utilisateur :** `Setting_widget` fournit des bascules et des options.
*   **Persistance :** Paramètres stockés dans `Foxy.json`.
*   **Paramètres Clés :**
    *   `sensitivity` : Contrôle le seuil d'analyse DL (0=Moyen, 1=Élevé).
    *   `extend_mode` : Active/désactive l'analyse YARA (0=Off, 1=On).
    *   `proc_protect`, `file_protect`, `sys_protect`, `net_protect` : Active/désactive les modules de protection en temps réel.
    *   `theme_color` : Stocke le nom du thème sélectionné ("White", "Red") ou le chemin vers le dossier du thème personnalisé.
    *   `language_ui` : Stocke le code de langue sélectionné ("en_US", "zh_TW", "zh_CN"). *Note : Le mécanisme de traduction réel a été supprimé, mais le paramètre demeure.*
    *   `white_lists` : Liste de chemins absolus (fichiers/dossiers) à exclure des analyses et du blocage.
    *   `block_lists` : Liste de dictionnaires (`{titre: nom_classe}`) définissant les fenêtres pour le bloqueur de popups.
*   **Moteur de Thèmes :**
    *   `init_config_color` définit les thèmes intégrés.
    *   `init_change_theme` gère les changements de sélection de l'interface utilisateur, y compris la demande d'un dossier si 'Personnalisé' est choisi.
    *   `init_change_color` applique le thème sélectionné (intégré ou chargé depuis `Color.json` personnalisé et fichier d'icône) en définissant des feuilles de style (`setStyleSheet`) sur les éléments de l'UI et les boutons bascules en fonction de leur texte ("Activé"/"Désactivé"). Inclut un repli vers le thème "Blanc" en cas d'erreur.
*   **Langue :** `init_change_lang` met à jour `config_json["language_ui"]` basé sur la sélection du bouton radio. `init_change_text` définit maintenant statiquement tout le texte de l'interface utilisateur en anglais, ignorant le paramètre de langue à des fins de traduction.

### 3.5. Interface Utilisateur (UI/UX)

*   **Framework :** PyQt5.
*   **Apparence :** Fenêtre sans cadre (`Qt.FramelessWindowHint`) avec dessin personnalisé (`paintEvent`) pour la forme/bordure. La barre de titre personnalisée permet le glissement (`mousePress/Move/ReleaseEvent`). Utilise `QGraphicsDropShadowEffect` pour la profondeur.
*   **Navigation :** Les boutons de la barre latérale (`State_Button`, `Virus_Scan_Button`, etc.) basculent entre les widgets de contenu principaux (`State_widget`, `Virus_Scan_widget`, etc.) en utilisant `_switch_main_widget`.
*   **Animations :** Utilise `QPropertyAnimation` et `QGraphicsOpacityEffect` pour des transitions fluides (fondu entrant, glissement entrant, déroulant, expansion/réduction) via les fonctions `change_animation*`.
*   **Feedback :** Fournit des informations via des boîtes de message (`info_event`, `question_event`), une zone de journal persistante (`State_output`), et des notifications de la zone de notification système (`QSystemTrayIcon`, `send_notify`).
*   **Réactivité :** Les tâches d'arrière-plan (analyse, surveillance) utilisent `threading.Thread`. Les mises à jour de l'interface utilisateur depuis les threads sont gérées en toute sécurité en utilisant `QMetaObject.invokeMethod` ou `QTimer.singleShot`. `QApplication.processEvents()` est appelé pendant les boucles potentiellement longues (construction de la liste des processus, suppression de fichiers) pour éviter le gel.

## 4. Dépendances

*   **Python 3.x**
*   **PyQt5 :** `pip install PyQt5`
*   **requests :** `pip install requests` (Bien qu'utilisé dans les imports, son utilisation n'est pas montrée dans l'extrait de code fourni - pourrait être pour de futures fonctionnalités cloud ou mises à jour).
*   **pyperclip :** `pip install pyperclip` (Pour copier du texte dans le presse-papiers).
*   **msvcrt :** Module Python intégré sous Windows (pour le verrouillage de fichiers).
*   **winshell (Optionnel) :** `pip install winshell` (Utilisé uniquement dans `clean_system` pour vider la Corbeille).

## 5. Exécution de l'Application

1.  Assurez-vous que toutes les dépendances sont installées.
2.  Placez les fichiers moteur nécessaires (`Foxy_Engine.py`, `Foxy_Suffixes.py`, fichiers de modèle dans `Engine/Model`, fichiers de règles dans `Engine/Rules`) et le fichier d'interface (`Foxy_Interface.py`) aux emplacements corrects par rapport au script principal.
3.  Placez les fichiers du pilote (`Install_Driver.bat`, `Uninstall_Driver.bat`, et le pilote lui-même) dans `Driver/Protect`.
4.  Exécutez le script Python principal : `python votre_nom_script_principal.py`
5.  **Privilèges Administrateur :** Exécuter en tant qu'Administrateur est **requis** pour que de nombreuses fonctionnalités principales fonctionnent correctement, y compris :
    *   Surveillance des fichiers en temps réel (`ReadDirectoryChangesW` sur C:\).
    *   Accès au MBR (`\\.\PhysicalDrive0`).
    *   Installation/démarrage/arrêt du service pilote (commandes `sc`).
    *   Accès/terminaison de certains processus système (`OpenProcess`, `TerminateProcess`).
    *   Écriture dans les clés de registre HKEY_LOCAL_MACHINE.
    *   Écriture de la configuration dans `C:/ProgramData`.

## 6. Limitations et Améliorations Futures

*   **Portée de la Surveillance Fichiers :** La protection des fichiers en temps réel ne surveille actuellement que la racine du lecteur C:\. Elle devrait idéalement surveiller tous les lecteurs pertinents ou des chemins configurables par l'utilisateur.
*   **Détection Antirançongiciel :** L'heuristique est basique (comptage des changements de type de fichier par un seul processus suivi). Une analyse comportementale plus sophistiquée est nécessaire.
*   **Limitation `track_proc` :** Seul le *dernier* processus analysé, non sur liste blanche et propre est suivi. Plusieurs processus agissant de manière suspecte pourraient être manqués. Un mécanisme de suivi plus robuste est nécessaire.
*   **Risque de Restauration MBR :** Restaurer automatiquement le MBR peut être dangereux si le MBR d'origine était déjà problématique ou si la modification était légitime (ex: mise à jour du chargeur de démarrage). La confirmation de l'utilisateur est incluse, mais le risque demeure.
*   **Complexité du Pilote :** La gestion des pilotes noyau ajoute une complexité significative et des problèmes potentiels de stabilité/compatibilité.
*   **Mises à Jour :** Aucun mécanisme de mise à jour de l'application, des moteurs d'analyse ou des signatures n'est implémenté.
*   **Évasion :** Les logiciels malveillants peuvent employer des techniques pour échapper aux méthodes de détection et de surveillance actuelles (ex: appels directs au noyau, process hollowing, désactivation de la surveillance).
*   **Plateforme :** Windows uniquement en raison de la forte dépendance à l'API Windows et `msvcrt`.
*   **Utilisation des Ressources :** Les threads de surveillance constants consomment des ressources. Des optimisations comme l'utilisation d'E/S asynchrones (ex: E/S superposées avec `ReadDirectoryChangesW`) pourraient améliorer l'efficacité.
*   **Gestion des Erreurs :** Bien que certains blocs `try...except` existent, la gestion des erreurs pourrait être plus granulaire et fournir un retour plus clair à l'utilisateur.
*   **Détails des Moteurs d'Analyse :** Le fonctionnement interne de `DLScan` et `YRScan` n'est pas détaillé ici.

**Améliorations Potentielles :**

*   Implémenter la surveillance de fichiers multi-lecteurs.
*   Ajouter l'analyse comportementale/sandboxing.
*   Améliorer `track_proc` ou utiliser un suivi de causalité alternatif.
*   Développer un mécanisme de mise à jour sécurisé.
*   Affiner l'UI/UX et le rapport d'erreurs.
*   Optimiser l'utilisation des ressources.
*   Ajouter le support pour plus de moteurs d'analyse ou des consultations cloud.
*   Implémenter des mécanismes d'auto-protection robustes au-delà du pilote optionnel.