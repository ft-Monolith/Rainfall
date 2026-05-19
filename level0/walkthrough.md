# Walkthrough — Rainfall : Level0

## Objectif

Obtenir le mot de passe de `level1` en exploitant le binaire `level0` (setuid `level1`).
Ici, il n’y a pas de buffer overflow : la logique est une **validation d’argument**.

---

## 1. Reconnaissance

### Permissions du binaire

```bash
ls -la
```

On repère que `level0` est setuid (bit `s`) et appartient à `level1`.
Donc si le binaire exécute un shell, ce shell héritera des droits `level1`.

---

## 2. Analyse du binaire

### Désassemblage de `main`

```bash
gdb ./level0
(gdb) disas main
```

Extrait clé :

```asm
mov    0xc(%ebp),%eax
add    $0x4,%eax
mov    (%eax),%eax
mov    %eax,(%esp)
call   atoi
cmp    $0x1a7,%eax
jne    ...
```

Interprétation :

1. Le programme récupère `argv[1]`
2. Le convertit en entier via `atoi(argv[1])`
3. Compare ce résultat à `0x1a7`
4. Si différent (`jne`), échec
5. Si égal, chemin succès (shell)

---

## 3. Trouver la bonne valeur

La constante est en hexadécimal : `0x1a7`.
Conversion :

$$
0x1a7 = 1 \times 16^2 + 10 \times 16 + 7 = 423
$$

Valeur attendue : **423**.

---

## 4. Exploitation

Lancer le binaire avec l’argument correct :

```bash
./level0 423
```

Si la comparaison réussit, un shell s’ouvre avec les droits `level1`.

---

## 5. Récupérer le mot de passe du niveau suivant

Dans le shell obtenu :

```bash
cat /home/user/level1/.pass
```

Puis se connecter :

```bash
su level1
# coller le mot de passe récupéré
```

---

## 6. Pseudo-code de la logique

```c
int main(int argc, char **argv) {
    int n = atoi(argv[1]);
    if (n == 0x1a7) {
        // shell avec droits effectifs level1 (setuid)
        spawn_shell();
    } else {
        // échec
    }
}
```

---

## 7. Points importants à retenir

- `atoi` convertit une chaîne en entier.
- `cmp $0x1a7, %eax` fixe la valeur exacte à fournir.
- `0x1a7` en décimal = `423`.
- Le bit setuid est la raison pour laquelle le shell donne les droits du niveau suivant.
