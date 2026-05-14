# Rainfall — CLAUDE.md

## Contexte du projet

Projet d'exploitation de binaires ELF sur architecture **i386** (32 bits).
L'objectif est de progresser de level0 à level9 (mandatory) puis bonus0 à bonus3 (bonus),
en lisant le fichier `.pass` du niveau suivant pour passer au niveau d'après.

---

## Connexion à la VM

```bash
ssh levelX@<IP_VM> -p 4242
# Premier accès : level0 / level0
# Si l'IP n'est pas affichée au boot : ifconfig
```

---

## Progression — Mandatory (TOUS obligatoires)

| Niveau | Répertoire | Statut |
|--------|-----------|--------|
| level0 | `level0/` | [ ] |
| level1 | `level1/` | [ ] |
| level2 | `level2/` | [ ] |
| level3 | `level3/` | [ ] |
| level4 | `level4/` | [ ] |
| level5 | `level5/` | [ ] |
| level6 | `level6/` | [ ] |
| level7 | `level7/` | [ ] |
| level8 | `level8/` | [ ] |
| level9 | `level9/` | [ ] |

## Progression — Bonus (évalués SEULEMENT si mandatory parfait)

| Niveau | Répertoire | Statut |
|--------|-----------|--------|
| bonus0 | `bonus0/` | [ ] |
| bonus1 | `bonus1/` | [ ] |
| bonus2 | `bonus2/` | [ ] |
| bonus3 | `bonus3/` | [ ] |

> Dernier utilisateur : `end`

---

## Structure EXACTE du repo (obligatoire)

Chaque niveau doit avoir exactement cette structure :

```
levelX/
├── flag            ← le contenu du fichier .pass (peut être vide, mais justifier)
├── source          ← le code source reconstitué du binaire (langage libre)
├── walkthrough     ← les étapes détaillées de l'exploitation
└── Ressources/     ← tout ce qui aide à prouver la solution (scripts, notes...)
```

### Règles critiques sur les fichiers

- **`flag`** : contenu exact du `.pass` lu — `cat /home/user/levelX/.pass`
- **`source`** : reconstruction lisible du binaire exploité (C, Python, pseudo-code...)
  - doit être compréhensible par n'importe quel développeur
  - langage libre, mais clair
- **`walkthrough`** : toutes les étapes de la solution, reproductibles pas à pas
- **`Ressources/`** : scripts d'exploit, GDB sessions, notes d'analyse, etc.
  - **AUCUN BINAIRE dans le repo** (ni dans Ressources ni ailleurs)
  - Les fichiers ISO/binaires du projet se téléchargent pendant l'évaluation, pas stockés

---

## Règles absolues — violations = échec ou -42

| Règle | Détail |
|-------|--------|
| **Pas de binaires** | Aucun binaire dans aucun dossier du repo |
| **Pas d'automation tool** | Utiliser un outil d'automatisation = -42 |
| **Pas de bruteforce** | Les flags SSH ne peuvent pas être bruteforcés |
| **Pas de root** | Devenir root = triche |
| **Pas de fichiers ISO** | Les fichiers du projet ISO ne vont PAS dans le repo |
| **Tout expliquer** | Chaque fichier du repo doit être justifiable en éval |
| **Noms exacts** | `flag`, `source`, `walkthrough`, `Ressources` — vérifier la casse |

---

## Workflow par niveau

```
1. Se connecter : ssh levelX@<IP> -p 4242
2. Analyser le binaire : file, strings, ltrace, strace, objdump, GDB/pwndbg
3. Décompiler/reverser → reconstruire le source
4. Trouver la vulnérabilité (buffer overflow, format string, heap, etc.)
5. Écrire l'exploit
6. Exécuter : ./levelX $(exploit) ou echo "payload" | ./levelX
7. Lire le pass : cat /home/user/levelX+1/.pass
8. Vérifier : su levelX+1 avec le pass obtenu
9. Documenter :
   - Écrire flag (le pass)
   - Écrire source (code reconstitué)
   - Écrire walkthrough (étapes reproduisibles)
   - Mettre les ressources utiles dans Ressources/
```

---

## Checklist avant soumission

- [ ] 10 dossiers mandatory (level0 à level9) présents
- [ ] Chaque dossier contient `flag`, `source`, `walkthrough`, `Ressources/`
- [ ] `flag` contient le bon `.pass`
- [ ] `source` est lisible et compréhensible
- [ ] `walkthrough` est reproductible étape par étape
- [ ] Aucun binaire dans le repo (`find . -type f -executable` doit retourner vide)
- [ ] Aucun fichier issu de l'ISO dans le repo
- [ ] Noms de dossiers/fichiers corrects (casse exacte)
- [ ] Chaque membre du groupe peut expliquer chaque level
- [ ] Bonus : seulement si mandatory 100% parfait

---

## Techniques d'exploitation courantes (i386)

- **Buffer overflow** — stack smashing, contrôle du RET
- **Format string** — `%x`, `%n`, lecture/écriture arbitraire
- **Heap overflow** — corruption de chunks malloc
- **GOT overwrite** — redirection de fonctions via la Global Offset Table
- **ret2libc** — appel de `system("/bin/sh")` sans shellcode
- **Shellcode injection** — NOP sled + shellcode sur la stack

### Outils utiles (à documenter dans Ressources si utilisés)

```bash
gdb ./binary          # débogage
objdump -d ./binary   # désassemblage
strings ./binary      # chaînes en clair
ltrace ./binary       # appels lib
strace ./binary       # appels système
file ./binary         # type du binaire
readelf -a ./binary   # headers ELF
python3 / pwntools    # construction de payloads
```

---

## Rappel évaluation

- Évaluation uniquement par des humains
- Chaque membre doit pouvoir justifier chaque solution
- Être prêt à reproduire l'exploit en live
- En cas de vrai bug du projet : contacter l'équipe pédagogique
