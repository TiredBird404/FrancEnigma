FrancEnigma est un projet expérimental développé par un élève, qui consiste en un algorithme de chiffrement symétrique. En combinant les principes de l'Enigma, la machine de chiffrement allemande de la Seconde Guerre mondiale, avec le chiffrement par octets et par blocs des ordinateurs modernes, il a mis au point un algorithme cryptographique fait maison. 

Comme il s'agit d'un projet personnel et qu'il n'a pas fait l'objet d'optimisations de performances ni d'audit de sécurité professionnel, son utilisation dans des situations de chiffrement réelles n'est pas recommandée.

# Architecture Principale
L'algorithme s'appuie sur la structure classique « rotors-réflecteur » de la machine Enigma, tout en y intégrant des mécanismes de sécurité contemporains pour garantir l'intégrité des données :
- Chiffrement de flux inspiré d'Enigma :
    - Rotors : Génération dynamique de 16 rotors au niveau octet (chacun contenant une permutation de 0 à 255). L'initialisation utilise l'algorithme de mélange de Fisher-Yates et un générateur de nombres aléatoires déterministe (`HashRandom`) basé sur SHA-256 et SHAKE-128.
    - Mécanisme de rotation (Stepping) : Les rotors tournent avec un pas variable (`rotation_strength`), incluant un système de retenue (carry) similaire aux mécanismes mécaniques originaux.
    - Réflecteur / Conversion : Simule la plaque de réflexion d'Enigma en effectuant une transformation XOR lors du retour du signal électrique.
- Diffusion:
    - Avant le chiffrement Enigma, le texte clair subit plusieurs cycles de diffusion : permutations de positions, additions modulaires dynamiques et chaînages XOR. Cette étape renforce considérablement l'effet d'avalanche face à d'infimes changements du texte source.
- Dérivation de clé moderne :
    - Utilisation de `PBKDF2-HMAC-SHA256` (avec 1 000 000 d'itérations) pour transformer la clé utilisateur et un sel aléatoire en deux clés distinctes : une clé de chiffrement (Cryption Key) et une clé d'authentification (MAC Key).
- Code d'Authentification de Message (MAC) :
    - Architecture de type **Encrypt-then-MAC**. Utilisation de `HMAC-SHA3-512` et `SHAKE-256` pour générer une étiquette de 16 octets, garantissant que les données n'ont pas été altérées lors du stockage ou de la transmission.

# Processus de Chiffrement
Le cycle complet d'une opération est le suivant :
1. **Génération du sel** : Création d'un sel aléatoire de 16 octets.
2. **Dérivation des clés** : `PBKDF2(UserKey + Version, Salt)` -> `Cryption Key` & `MAC Key`.
3. **Diffusion** : `Diffusion(TexteClair, Cryption Key)` pour la confusion initiale.
4. **Chiffrement Enigma** : `FrancEnigma(Cryption Key)` applique le chiffrement de flux sur les données diffusées.
5. **Génération du MAC** : Calcul de l'étiquette via `MAC(DonnéesChiffrées, MAC Key)`.
6. **Sortie finale** : Concaténation `Sel` + `Données Chiffrées` + `MAC`.

# Informations Techniques
- **Compatibilité** : Python 3.9 ou supérieur.
- **Dépendances** : Utilise exclusivement la bibliothèque standard de Python, aucune installation tierce n'est requise.
