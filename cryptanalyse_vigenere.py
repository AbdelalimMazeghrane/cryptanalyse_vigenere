# Sorbonne Université 3I024 2023-2024
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : Mazeghrane Abdelalim 21113014
# Etudiant.e 2 : Baly Luka 21104733

import sys, getopt, string, math



# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"



# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [72501,8148,23748,29538,135149,8608,8353,8434,59075,3016,55,48291,20852,55326,38669,18648,7995,52009,61511,58029,50017,12945,9,3204,1810,965]

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    cette fonction prend une chaine de caracteres et effectue un decalge vers la droite
     en fonction de la cle key afin de la chiffrer
    """
    s=""
    for c in txt:
        n=ord(c)+key
        if(n>90):
            s += chr((n%90)+65-1)
        else:
            s += chr(n)
        
    return s

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    cette fonction prend une chaine de caracteres et effectue un decalge vers la gauche
     en fonction de la cle key afin de la dechifrer
    
    """
    s=""
    for c in txt:
        n=ord(c)-key
        if(n>=65):
            s += chr(n)
        else:
            s += chr(n+26)
    return s

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    fonction pour le chiffrement de vigenere
    """
    s=""
    i=0
    for c in txt:
        s += chiffre_cesar(c,key[i%len(key)])
        i += 1

    return s

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    fonction pour le dechiffrement de vigenere
    """
    s=""
    i=0
    for c in txt:
        s += dechiffre_cesar(c,key[i%len(key)])
        i += 1

    return s

# Analyse de fréquences
def freq(txt):
    """
    string -> [int]
    Renvoie un tableau avec le nombre d'occurences de chaque lettre de l'alphabet 
    """
    
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    l=[0.0]*len(alphabet)
    for c in alphabet:
        nb=0
        for s in txt:
            if(c==s):
                nb += 1
        l[(ord(c)-ord('A'))%26]=nb
		
	
    hist=[0.0]*len(alphabet)
    return l

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    string -> int
    Renvoie la position dans l'alphabet de la lettre qui apparaît le plus grand nombre de fois dans le texte. 
    Si plusieurs lettres apparaissent autant de fois, on renverra celle qui apparaît la première dans
    l'ordre alphabétique.
    """
    l=freq(txt)
    mx=l[0]
    ind=0
    for i in range(0,len(l)):
        if(l[i]>mx):
            mx=l[i]
            ind=i
    return ind

# indice de coïncidence
def indice_coincidence(hist):
    """
    [int] -> double
    Renvoie l'indice de coïncidence
    hist: tableau qui correspond aux occurences des lettres d'un texte
    """
    n=sum(hist)*(sum(hist)-1)
    ni=0
    for i in hist:
        ni += i*(i-1)
    
    return ni/n

# Recherche la longueur de la clé
def colonnes_txt(cipher,keylen):
    """
        permet de recuerer les colones du textes
    """
    col=[]
    for j in range(0,keylen):
        s=""
        k=j
        while(k<len(cipher)):
            s += cipher[k]
            k += keylen
                
        col.append(s)
    return col


def longueur_clef(cipher):
    """
    string -> int
    Renvoie la taille du clef de message 
    cipher: le message encode
    hyp: la clef cherchée est au plus de longueur 20
    """
    
    lk=0
    for i in range(1,21):
        
        ind=colonnes_txt(cipher,i)
        
        ic=0
        for z in ind:
            ic += indice_coincidence (freq(z))
            
        
        
        if(ic/len(ind)>0.06):
            lk=i
            break
            
    

        
    return lk
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne

def clef_par_decalages(cipher, key_length):
    """
    string * int -> [int]
    cipher: un texte
    key_length: la taille de la cle
    Renvoie la clé sous forme d'une table de décalages 
    """
    decalages=[0]*key_length
    col=colonnes_txt(cipher,key_length)
    
    k=0
    for i in col:
        ind=lettre_freq_max(i)
        if(ind<(ord('E')-65)):
            
            decalages[k]=26-abs((ord('E')-65)-ind)
        else:
            decalages[k]=abs((ord('E')-65)-ind)

        k += 1
    
    return decalages


# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    string -> string
    Cryptanalyse de Vigenere avec decalages par frequence max
    cipher: le texte a analyser
    Remarque: la fonction analyse correctement 18 textes. C'est normal d'avoir une chiffre si petite, car
    en decodant chaque colonne, on regarde uniquement la lettre la plus presente. 
    On suppose que la lettre la plus frequente soit E, alors que ce n'est pas le cas tout le temps.
    QUESTION 9 -- Première cryptanalyse : 


    Comment expliquez-vous cela ?
    -> On explique cela car pour des textes courts, la fréquence d'apparition de certaines lettres ne coincident
    pas avec la fréquence des lettres d'une certaine langue. De plus, les textes qui ont été correctement cryptanalysés 
    sont des textes avec une apparition fréquente de la lettre E et A et/ou des textes longs. 
    Cette crypanalyse est inefficace sur les textes courts.


    """
    return dechiffre_vigenere(cipher,clef_par_decalages(cipher,longueur_clef(cipher)))



################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    [int] * [int] * int -> float
    Renvoie l'indice de coïncidence du texte 1 et du texte 2 qui aurait été décalé de d positions 
    (comme par un chiffrement de César)
    h1: tableaux qui correspond aux fréquences des lettres du premier texte
    h2: tableaux qui correspond aux fréquences des lettres du premier texte
    d: entier de decalage des textes
    """
    n=sum(h1)*sum(h2)
    occ=0
    for i in range(0,len(h1)):
        occ = occ + h1[i] * h2[(i+d)%26]
    return occ/n

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    string * int -> [int]
    Calcule pour chaque colonne son décalage par rapport à la première colonne
    cipher: le texte a dechiffrer
    key_length: la longueur de clef
    """
    decalages=[0]*key_length
    col=colonnes_txt(cipher,key_length)
    
    k=0
    for i in col:
        d=0
        tmp=0
        for j in range(0,26):
            icm=indice_coincidence_mutuelle(freq(col[0]),freq(i),j)
            if(icm>tmp):
                d=j
                tmp=icm
        
        decalages[k]=d
        k += 1
    
    return decalages

# Cryptanalyse V2 avec décalages par ICM

def cryptanalyse_v2(cipher):
    """
    string -> string
    Cryptanalyse de Vigenere avec decalages relatifs (avec l'indice de coincidence mutuelle)
    cipher: le texte a analyser
    """
   
    keylen=longueur_clef(cipher)
    dec=tableau_decalages_ICM(cipher,keylen)
    
    
    
    col=colonnes_txt(cipher,keylen)
    
    
    txt=""
    k=0
    for i in col:
        col[k] = dechiffre_cesar(i,dec[k])
        k += 1
    
   

    newtxt=""
    for j in range(max(map(len, col))):
    # Parcourir chaque colonne et récupérer le caractère à la position j si elle existe
        for i in range(keylen):
            if j < len(col[i]):
                newtxt += col[i][j]


    
    ind=lettre_freq_max(newtxt)
    
    if(ind<(ord('E')-65)):
        txt=dechiffre_cesar(newtxt,26-abs((ord('E')-65)-ind))
        
    else:
        txt=dechiffre_cesar(newtxt,abs((ord('E')-65)-ind))
    
    
    
    return txt



#### Combien de textes sont correctement cryptanalysés ?
# 43 ont été correctements cryptanalysés.

#### Comment expliquez-vous cela ?
# -> On explique cela car une cryptanalyse par indice de coincidence mutuelle
# est plus précise qu'une analyse simple par fréquence de lettre, elle attaque la clef et 
# le décalage. 
# Cependant elle continue à comparer avec la fréquence des lettres de la langue et
# reste donc inefficace sur les textes courts.

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    [int] * [int] -> float
    Renvoie la correlation entre deux listes de meme taille
    L1: la premiere liste
    L2: la deuxieme liste
    """
    xbar=sum(L1)/len(L1)
    ybar=sum(L2)/len(L2)
    
    up=0.0
    downX=0.0
    downY=0.0
    for i in range(len(L1)):
        up = up + (L1[i]-xbar)*(L2[i]-ybar)
        downX = downX + (L1[i]-xbar)**2
        downY = downY + (L2[i]-ybar)**2
    
    return round(up / ((math.sqrt(downX) * math.sqrt(downY))),4)
# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    string * int -> (float, string)
    """
    key=[0]*key_length
    score = 0.0
    liste_correlation=[0]*key_length

    col=colonnes_txt(cipher,key_length)
    
    k=0
    for c in col:
        max=0
        d=0
        for i in range(0,26):
            dec=dechiffre_cesar(c,i)
            tmp=correlation(freq_FR,freq(dec))
            if(tmp>max):
                max=tmp
                d=i
        key[k]=d
        liste_correlation[k]=max
        k += 1
    
    score=sum(liste_correlation)/len(liste_correlation)

    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    string -> string
    Cryptanalyse de Vigenere avec correlation
    cipher: le texte a analyser
    """
    max=0
    key=[]
    for i in range(1,21):
        t=clef_correlations(cipher,i)
        if(t[0]>max):
            max=t[0]
            key=t[1]
    

    return dechiffre_vigenere(cipher,key)

#Combien de textes sont correctement cryptanalysés ?
# 94 ont été correctement cryptanalysés.

#### Quels sont les caractéristiques des textes qui échouent ?
# -> exemple de textes correctement cryptanalysés :
# texte 1 : texte long, clé de taille moyenne
# -> exemple de textes qui échouent :
# texte 81 : texte court, clé longue
# texte 86 : texte court, clé longue 
# Les textes qui échouent n'ont pas la meme fréquence de lettres par rapport à celle de 
# la langue française (plus de l que de u pour le texte 89)

#### Comment expliquez-vous cela ?
# 
# -> Nous avons réussi a cryptanalysés plus de textes que les méthodes précédentes.
# Mais encore une fois, la longueur des textes a un impact et l'utilisation des
# fréquences d'une langue aussi. Le chiffrement de vigenere est un bon cryptosystème
# sur les textes courts à clé longue mais pas sur les textes longs facilement déchiffrable.


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
