#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
//-----------------------------------------------------------------------------------------------//
//TP 2 Systeme d'exploitation : Minishell pour la gestion des fichiers et repertoire
//---------------------------------les structeur de donnees--------------------------------------//
typedef struct tm TEMPS;

typedef struct inode{
/* Structure utilisee pour representer un inode*/
    char type;//d ou f
    char mode[10];
    int  UID;
    int  GID;
    unsigned int taille;
    char timeCreation[40];
    char timeAcces[40];
    char timeModification[40];
    int premiersBlocs[10];
    int inSimple;//stocke l'indice de blocDisque correspondant à indirection simple
    int inDouble;//stocke l'indice de blocDisque correspondant à un blocDisque de type   
                 //inSimpleindirection simple qui a dans chaque champs indice d'un blocDisque
                 //de type inSimple
}INODE;

typedef struct ligneBloc{
/* Structure utilisee pour representer une ligne bloc, avec un nom de fichier et un numero d'inode*/
    char nom[129];
    int  noInode ;
}LIGNEBLOC;

struct ligneBloc blocRep[15];

typedef union blocDisque{
    struct 	inode i;
    struct  ligneBloc  blocRep[15];
    int  inSIMPLE[512];
    int  inDOUBLE[512];
    char  alignement[2048];//just pour fixer la taille d'un bloque Ã  2k
}BLOCDISQUE;

enum listeCMD {/*liste de commandes*/
    CMD_MKDIR, CMD_RMDIR, CMD_CD, CMD_LS, CMD_CRF, CMD_CP, CMD_RM, CMD_MV, CMD_BLC,
    CMD_LOGOUT, CMD_NULLE, CMD_INVALIDE
};

enum optCMD {/*liste d'options possible pour les commandes*/
    OPT_OBL, OPT_OPT, OPT_NON, PAR_NON, PAR_INT
};

struct syntaxeCmd {/*structure general d'un syntax*/
    char * nom;
    enum listeCMD noCmd;
    char option;
    enum optCMD inode1;
    enum optCMD inode2;
    enum optCMD param;
};

struct inodePNomE{/* pour stocker le path*/
    char *nom;
    int inodeP;
    int inodeE;
};
    
struct Cmd {/* structure general d'une commande*/
    enum listeCMD noCmd;
    char option;
    struct inodePNomE path1;
    struct inodePNomE path2;
    int param;
};
    
struct syntaxeCmd listeCmd[] = {
// -----------------structure de commades--------------//
    {"mkdir", CMD_MKDIR, ' ', OPT_OBL, OPT_NON, PAR_NON },
    {"rmdir", CMD_RMDIR, ' ', OPT_OBL, OPT_NON, PAR_NON },
    {"cd", CMD_CD, ' ', OPT_OPT, OPT_NON, PAR_NON },  
    {"ls", CMD_LS, 'l', OPT_OPT, OPT_NON, PAR_NON },  
    {"crf", CMD_CRF, ' ', OPT_OBL, OPT_NON, PAR_INT },
    {"cp", CMD_CP, ' ', OPT_OBL, OPT_OBL, PAR_NON },  
    {"mv", CMD_MV, ' ', OPT_OBL, OPT_OBL, PAR_NON },      
    {"rm", CMD_RM, ' ', OPT_OBL, OPT_NON, PAR_NON },
    {"blc", CMD_BLC, ' ', OPT_OBL, OPT_NON, PAR_NON },
    {"logout", CMD_LOGOUT, ' ', OPT_NON, OPT_NON, PAR_NON },
    {"", CMD_NULLE, ' ', OPT_NON, OPT_NON, PAR_NON }
};

const int NB_CMD = sizeof(listeCmd)/sizeof(struct syntaxeCmd);//Bruno
//---------------------------LIMITS------------------------//
    /* nbMax de fichiers et reps = 103 */
    /* Si il y a un reperoire avec un nom et on veut cree un fichier avec meme nom dans meme parent 
     * il l'accept pas */
//-----------------------------------------------------------------------------------------------//
//-------------------declaration des prototypes des fonction a utiliser--------------------------//
#define NB_MAX_BLOC 52224 /* Constante pour le nombre de blocs de donnees maximum qu'on peut creer */
#define NB_MAX_INODE 9216 /* Nombre maximum de Inodes que on peut avoir */
#define NB_MAX_BLC 1920   /* Nombre maximum de BLOCDISQUE de taille 2k que on peut avoir */

int initializer();
int cmd_cd(struct Cmd *cmd);
int cmd_rmDir(struct Cmd *cmd);          void removeDir(int inode, int inodeP);
int cmd_crf(struct Cmd *cmd);
int cmd_Cp_Mv_Rm (struct Cmd *cmd);      int cmd_rm(int inode);
int cmd_blc(struct Cmd *cmd);
int cmd_ls(struct Cmd *cmd);
int cmd_mkdir(struct Cmd *cmd);
int updateParent(int noInodeP, int inodeCourant, char nom[129], int inode , int checkUpdate);
int returnInodeParent(int noInode);
int retournNoInode(char *nom, int inodeP);
int updateInode(int inodeDest, int inodeSource, int identifierInode);
void recupererSousChaine(char * ptrBuffer, char * delimiteur, char ** tabSousChaine);
struct inodePNomE validerPath(char *chaine);
int nbElement(char ** tabSousChaine);
int premierInodeLibre();
int allouerBlocLibres();
int allouerSpace(int nbBlocs, INODE *iInode);
void libererSpace(int nbBlocs, INODE *iInode);
void liberer(int b);
void recupererTemps(char * timeString, int taille);
int validerCmd(char *ligneCmd, struct Cmd * cmd, char **tabSousChaine);
int afficherPrompt();
void initPremierBloc(int *tab) ;
int avoirEnfant(INODE *iInode);
int validerNom(char *nomDonne);
//-----------------------------------------------------------------------------------------------//
//--------------------------------------Les variables globals------------------------------------//
union blocDisque * tableauBloc = NULL;// espce alooue dynamiquement pour les bolcs

int nbBlocsAllouers = 0;

int tabInode[NB_MAX_INODE] ;//tableu d'inodes contien les numeros de blocs

unsigned int *blocLibres = NULL; //tableu blocLibre

int repCourant = 0;//noInode courant initializé à zero pour la Racine

const char sRep = '#';
const char * modeDir = "rwxr-xr-x"; //mode access pour un repertoir par defut
const char * modeFic = "rw-r--r--"; //mode access pour un fichier par defut
//-----------------------------------------------------------------------------------------------//
//-----------------------------------------MAIN--------------------------------------------------//
    
int main(int argc, char** argv){
    char  buffer[2000];
    char * ptrBuffer;
    char * tabSousChaine[100] ;//pour stocker la chaine de commande entree par utilisateur
    struct Cmd cmd;
    size_t  nbreBytes = 1000;
    int  valeur = 0;
    pid_t pid;
    ptrBuffer = buffer;

    pid = fork();
    if(pid < 0){
        printf("Echec fork");
    }else if(pid == 0){
        execlp("clear", "clear", NULL);
    }else{
        wait(NULL);
 
    initializer();// initializer la Racine
        do {
            afficherPrompt();
            valeur = getline(&ptrBuffer, &nbreBytes, stdin);
            validerCmd(ptrBuffer,  &cmd, tabSousChaine);

            switch (cmd.noCmd) {
                case CMD_MKDIR:
                    cmd_mkdir(&cmd);
                    break;
                case CMD_RMDIR:
                    cmd_rmDir(&cmd);
                    break;
                case CMD_CD:
                    if(tabSousChaine[1]==NULL){
                        cmd.path1.inodeE = 0;
                        cmd.path1.inodeP = 0;
                    }
                    cmd_cd(&cmd);
                    break;
                case CMD_LS:
                    if(tabSousChaine[1]!=NULL){ 
                        if(cmd.option!=' '){//si il y une option
                            if(tabSousChaine[2]!=NULL){//si il y a une chemin donnée
                                if(cmd.path1.inodeE==-1 || cmd.path1.inodeP==-1){//
                                        fprintf(stderr,"erreur: path inexistant\n");
                                        break;
                                }
                            }else{
                                cmd.path1.inodeE = repCourant;//si il n'y a pas une chemin donnée
                            }
                        }else if(cmd.path1.inodeE==-1 || cmd.path1.inodeP==-1){
                            fprintf(stderr,"erreur: path inexistant\n");
                            break;
                        }
                    }else{
                        cmd.path1.inodeE = repCourant;
                    }
                    cmd_ls(&cmd);
                    break;
                case CMD_CRF:   
                    cmd_crf(&cmd);
                    break;
                case CMD_CP:
                    cmd_Cp_Mv_Rm(&cmd);
                    break;
                case CMD_RM:
                    cmd_Cp_Mv_Rm(&cmd);
                    break;
                case CMD_MV:
                    cmd_Cp_Mv_Rm(&cmd);
                    break;
                case CMD_BLC:
                    cmd_blc(&cmd);
                    break;
                case CMD_LOGOUT:
                    printf("\n**************************Fin normale du programme**************************\n\n\n\n");
                    break;
                case CMD_NULLE:
                    break;
                case CMD_INVALIDE:
                    printf("commande invalide\n");
                    break;
                default:
                    printf("Bug\n");
            }

        }while(cmd.noCmd != CMD_LOGOUT);
    }
   return 0;
}
//les fonctions:--------------------------------------------------------//

int validerCmd(char *ligneCmd, struct Cmd * cmd, char **tabSousChaine) {//Bruno
/* Elle valide la commande donne et trouve inodes de path source et destination */
    recupererSousChaine(ligneCmd," \n", tabSousChaine);
    int noArg=0;
    int nbArg = nbElement(tabSousChaine);
    int i;

    cmd->noCmd = CMD_NULLE;
    cmd->option = ' ';
    cmd->path1.inodeE = -1;/**/
    cmd->path1.inodeP = -1;/**/
    cmd->path2.inodeE = -1;/**/
    cmd->path2.inodeP = -1;/**/
    cmd->param = 0;

    if (nbArg == 0 ) return 0;
    for(i=0; i<NB_CMD; i++){
        if(strcmp(tabSousChaine[noArg], listeCmd[i].nom)==0){
            cmd->noCmd = listeCmd[i].noCmd;
            noArg++;
            if(listeCmd[i].option!=' ' && noArg < nbArg){// option optionelle /*ls
                if(tabSousChaine[noArg][0]=='-'){
                    if(strlen(tabSousChaine[noArg]) >1 && tabSousChaine[noArg][1]==listeCmd[i].option){
                        cmd->option = listeCmd[i].option;
                        noArg++;
                    }else {
                        break;
                    }
                }
            }
            
            if(listeCmd[i].inode1==OPT_OBL){// path 1 obligatoir/*mkdir rmdir rm cp mv blc crf
                 if (noArg < nbArg) {
                     cmd->path1 = validerPath(tabSousChaine[noArg]);
                     noArg++;
                 }else {
                     break;
                 }
            }else if(listeCmd[i].inode1==OPT_OPT && noArg < nbArg) {// path 1 optionelle/*ls cd
                    
                cmd->path1 = validerPath(tabSousChaine[noArg]);/**/
                     noArg++;
            }

            if(listeCmd[i].inode2==OPT_OBL){// path 2 obligatoir/*cp mv 
                if (noArg < nbArg) {
                    cmd->path2 = validerPath(tabSousChaine[noArg]);
                    noArg++;
                }else {
                    break;
                }
            }else if(listeCmd[i].inode2==OPT_OPT && noArg < nbArg) {
                    cmd->path2 = validerPath(tabSousChaine[noArg]);
                    noArg++;
            }

            if(listeCmd[i].param == PAR_INT){//crf
                if (noArg < nbArg) {
                    cmd->param = atoi(tabSousChaine[noArg]);
                    noArg++;
                }else {
                    break;
                }
            }
            if (noArg < nbArg) {
                // trop d'arguments
                break;
            }

            return 0;
        }
    }
    cmd->noCmd = CMD_INVALIDE;
    return 0;
};

int initializer(){	       
/* Elle cree la Racine "/" */
    blocLibres = (unsigned int *)realloc(blocLibres,120*sizeof(unsigned int));
    int cnt;
    for(cnt = 0; cnt<120 ;cnt++){
        blocLibres[cnt]=0;
    }
    //initialization du tabInode à -1;
    int j;
    for(j = 0; j<NB_MAX_INODE ;j++){
        tabInode[j]=-1;
    }
    //numero de preomier blocDisque libre dans le tableauBloc
    int noBlocLibre1 = allouerBlocLibres();
    tabInode[premierInodeLibre()] = noBlocLibre1;
    
    INODE *iInodeR = &tableauBloc[tabInode[0]].i;  
    iInodeR->type = 'd';
    strcpy(iInodeR->mode, modeDir);
    iInodeR->UID = 1;
    
    char timeString[40];
    recupererTemps(timeString, 40);
    strcpy(iInodeR->timeCreation,timeString);
    strcpy(iInodeR->timeAcces,timeString);
    strcpy(iInodeR->timeModification,timeString);
    
    int k;
    for (k=0; k<10; k++){
        tableauBloc[noBlocLibre1].i.premiersBlocs[k]=-1;
    }
    
    int noBlocLibre2 = allouerBlocLibres();
    tableauBloc[noBlocLibre1].i.premiersBlocs[0] = noBlocLibre2;
    
    strcpy(tableauBloc[noBlocLibre2].blocRep[0].nom, ".");
    tableauBloc[noBlocLibre2].blocRep[0].noInode = 0;
    strcpy(tableauBloc[noBlocLibre2].blocRep[1].nom, "..");
    tableauBloc[noBlocLibre2].blocRep[1].noInode = 0;
    repCourant = 0;

    int i;
    for (i=2; i<15; i++) {
        tableauBloc[noBlocLibre2].blocRep[i].noInode = -1;
        strcpy(tableauBloc[noBlocLibre2].blocRep[i].nom," ");
    }
    return 0;    
}

int cmd_ls(struct Cmd *cmd){
/* Elle liste le contenu d'un repertoire dans differents mode: ls, ls [chemin], ls -l, ls -l [chemin] */
    int cnt = 0;// un counteur pour ls pour ranger les noms de fichiers
    INODE *inodeLS = &tableauBloc[tabInode[cmd->path1.inodeE]].i;
    INODE *inodeLSP = &tableauBloc[tabInode[cmd->path1.inodeP]].i;
    if(inodeLS->type!='d' || inodeLSP->type!='d'){
        fprintf(stderr,"erreur: path inexistant\n");
        return 0;
    }
    int i = 0;
    while(i<10){
        if(inodeLS->premiersBlocs[i]>0){
            int j=0;
            while(j<15){ 
                int inodeF = tableauBloc[inodeLS->premiersBlocs[i]].blocRep[j].noInode;
                if(inodeF>-1){
                    INODE *iInodeF = &tableauBloc[tabInode[inodeF]].i;
                    char *nom = tableauBloc[inodeLS->premiersBlocs[i]].blocRep[j].nom;
                    if(cmd->option == 'l'){
                        printf("%c%10s  golrokh %4d  %11s  %s\n", iInodeF->type ,iInodeF->mode, iInodeF->taille, iInodeF->timeModification ,nom );
                    }else{
                        printf("%-15s", nom);
                        cnt++;
                    }
                }
                j++;
            }
        }
        i++;    
    }
    if(cmd->option!='l'){
        printf("\n");
    }else{
        if (cnt%6!=0) {
            printf("\n");
        }
    }
    return 0; 
}

int cmd_mkdir(struct Cmd *cmd){
/* Elle creer un repertoire */
    if (cmd->path1.inodeE > 0) {   /**/
        fprintf(stderr,"erreur: le répertoire existe déjà\n");
        return -1;
    }
    if(cmd->path1.inodeP<0){
        fprintf(stderr,"erreur: path inexistant\n");
        return -1;
    }
    if(validerNom(cmd->path1.nom)==-1){
        fprintf(stderr,"erreur: nom\n");
        return -1;
    }
    int noInode = premierInodeLibre();
    if(noInode==NB_MAX_INODE){
        fprintf(stderr,"erreur: la memoir est plein\n");
        return -1;
    }
    int noBlocLibre1 = allouerBlocLibres(); 
    
    if(noBlocLibre1==-1){
        fprintf(stderr,"erreur: la memoir est plein\n");
        tabInode[noInode] = -1;
        return -1;
    }
    
    tabInode[premierInodeLibre()] = noBlocLibre1;
    INODE *indRep = &tableauBloc[noBlocLibre1].i;
    indRep->type = 'd';
    
    strcpy(indRep->mode, modeDir);
    indRep->UID = 1;
    
    char timeString[40];
    recupererTemps(timeString, 40);
    strcpy(indRep->timeCreation,timeString);
    strcpy(indRep->timeAcces,timeString);
    strcpy(indRep->timeModification,timeString);
    int k;
    for (k=0; k<10; k++){
        indRep->premiersBlocs[k]=-1;
    }
    indRep->inSimple = -1;
    indRep->inDouble = -1;
    int noBlocLibre2 = allouerBlocLibres();
    if(noBlocLibre2==-1){
        fprintf(stderr,"erreur: la memoir est plein\n");
        tabInode[noInode] = -1;
        liberer(noBlocLibre1);
        return -1;
    }
    indRep->premiersBlocs[0] = noBlocLibre2;
    struct ligneBloc *rep = tableauBloc[noBlocLibre2].blocRep;
    
    strcpy(rep[0].nom, ".");
    rep[0].noInode = noInode;
    strcpy(rep[1].nom, "..");
    rep[1].noInode = repCourant;
    int control = updateParent(cmd->path1.inodeP, noInode, cmd->path1.nom , -1, 1);
    if(control==-1){// si ajouter n'est pas effectue
        liberer(noBlocLibre1);//inode
        liberer(noBlocLibre2);//blocDisque
        tabInode[noInode] = -1;
        return 0;
    }
    int i;
    for(i = 2; i<15;i++){
        tableauBloc[noBlocLibre2].blocRep[i].noInode = -1;
        strcpy(tableauBloc[noBlocLibre2].blocRep[i].nom," ");
    }
    return 0;
}

struct inodePNomE validerPath(char *chaine){
/* Elle valide un chemin par rapport a longueur de chemin donne et l'inode de premier rep dans le chemin et stocker le path dans un struc inodePNomE */
    struct inodePNomE stInodePNomE;
    int tmpParent = -1;
    char *tab2[100];
    int hauteur;
    stInodePNomE.inodeP = repCourant;
    stInodePNomE.inodeE  = -1;
    if (*chaine == '/') {// si le path commence par "/"
        stInodePNomE.inodeP = 0;
    }
    if(strcmp(chaine,"/")==0 || strcmp(chaine,"\n")==0){//si le path est "/"
        stInodePNomE.inodeE = 0;
        stInodePNomE.inodeP = 0;
        stInodePNomE.nom = "/";
        return stInodePNomE;
    }
    recupererSousChaine(chaine, "/", tab2);
    hauteur = nbElement(tab2);
    stInodePNomE.nom = tab2[hauteur-1];
    int i = 0;
    for (i=0; i<hauteur; i++){
        stInodePNomE.inodeE = retournNoInode(tab2[i], stInodePNomE.inodeP);
        tmpParent = stInodePNomE.inodeP;
            stInodePNomE.inodeP = stInodePNomE.inodeE;
    }
    stInodePNomE.inodeP = tmpParent;
    return stInodePNomE;
}

int cmd_cd(struct Cmd *cmd){
/* Elle change le repertoire courant vers celui specifie dans la commande cmd */ 
    if(cmd->path1.inodeE==-1 || cmd->path1.inodeP==-1){
        fprintf(stderr, "erreur: path inexistant\n");
        return 0;
    }
    if(strcmp(cmd->path1.nom, "/")==0){
        repCourant = 0;
    }else if(strcmp(cmd->path1.nom, "..")==0){
        repCourant = returnInodeParent(repCourant);
    }else{
        repCourant = cmd->path1.inodeE;
    }    
    return 0;
}

int cmd_rmDir(struct Cmd *cmd){
/* Elle efface un repertoire avec tous ses fichiers*/
    if(cmd->path1.inodeE<0||cmd->path1.inodeP<0){
        fprintf(stderr,"path inexistant\n");
        return 0;
    }
    int blocRepR;
    INODE *iInode = &tableauBloc[tabInode[cmd->path1.inodeE]].i;
    if(iInode->type=='d'){    
        if(avoirEnfant(iInode)==1){
            printf("Suppression impossible : le répertoire contient des sous répertoires ou des fichiers\n");
        }else{
           updateParent(cmd->path1.inodeP, -1, " ", cmd->path1.inodeE,0); 
           liberer(tabInode[cmd->path1.inodeE]);
           blocRepR = iInode->premiersBlocs[0];
           liberer(blocRepR);
           liberer(tabInode[cmd->path1.inodeE]);
           tabInode[cmd->path1.inodeE] = -1;
        }
    }else{
        fprintf(stderr,"path inexistant\n");
    }
return 0;    
}

int avoirEnfant(INODE *iInode){
/* Elle efface un repertoire/fichier par son inode et inode de son parent */
    int bool_avoirEnfant = 0;
    int i = 0;
    while(i<10 && bool_avoirEnfant == 0){
        int j = 0;
        if(i==0){
            j=2;
        }
        if (iInode->premiersBlocs[i]>-1) {
            while(j<15 && bool_avoirEnfant == 0){
                int ind = tableauBloc[iInode->premiersBlocs[i]].blocRep[j].noInode;
                if(ind>-1){
                    bool_avoirEnfant = 1;
                }
                j++;
            }
        }
        i++;
    }
    return bool_avoirEnfant;
}

int cmd_crf(struct Cmd *cmd){
/* Elle cree un fichier de nom et taille donnes dans le command cmd */
    char timeString[40];
    int nbBlocs;
    int noInode;
    int noBlocLibre;
    recupererTemps(timeString, 40);
    if (cmd->path1.inodeP==-1) {
        fprintf(stderr,"path inexistant\n");
        return 0;
    }
    if(validerNom(cmd->path1.nom)==-1){
        fprintf(stderr,"erreur: nom\n");
        return -1;
    }
    if(cmd->path1.inodeE==-1){
        nbBlocs = (cmd->param/2);
        if(nbBlocs >= NB_MAX_BLOC){
               fprintf(stderr,"impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
           return -1;
        }
        if(cmd->param%2!=0)	nbBlocs++;

        noInode = premierInodeLibre();
        if(noInode==NB_MAX_INODE){
            fprintf(stderr,"erreur: la memoir est plein\n");
            return -1;
        }
        noBlocLibre = allouerBlocLibres(); 
        if(noBlocLibre==-1){
            fprintf(stderr,"erreur: la memoir est plein\n");
            return -1;
        }

        tabInode[noInode] = noBlocLibre;
        INODE *indFic = &tableauBloc[noBlocLibre].i;
        int k;
        for (k=0; k<10; k++){
            tableauBloc[noBlocLibre].i.premiersBlocs[k]=-1;
        }
        indFic->inSimple = -1;
        indFic->inDouble = -1;
        indFic->type = 'f';
        strcpy(indFic->mode, modeFic);
        indFic->UID = 1;
        indFic->taille = cmd->param;
       
        strcpy(indFic->timeCreation,timeString);
        strcpy(indFic->timeAcces,timeString);
        strcpy(indFic->timeModification,timeString);
        int checkAlloue = allouerSpace(nbBlocs, indFic);
        if(checkAlloue!=0){// cas de espace memoire pleine
            libererSpace(checkAlloue, indFic);
            tabInode[noInode]=-1;
            liberer(noBlocLibre);
            return -1;
        }
        int control = updateParent(cmd->path1.inodeP, noInode, cmd->path1.nom, -1, 1);
        if(control==-1){// si ajouter n'est pas effectue
            liberer(noBlocLibre);
            tabInode[noInode] = -1;
            return 0;
        }
    }else{
        fprintf(stderr,"ce fichier deja existe\n");
    }
    return 0;
}

int cmd_Cp_Mv_Rm (struct Cmd *cmd){
/* Elle copie et deplacer un fichier source vers un fichier de destination et supprimer un fichier */
    INODE *ind;
    INODE *indSource;
    int noInodeRDest;
    int noInodeDest;
    char *nom;
    int checkUpdate;
    if(cmd->path1.inodeE<0){
        fprintf(stderr,"erreur path inexistant de Source\n");
        return 0;
    } 
    indSource = &tableauBloc[tabInode[cmd->path1.inodeE]].i;
    if(indSource->type=='d'){
        fprintf(stderr,"erreur path le %s n'est pas un fichier\n",cmd->path1.nom);
        return 0;
    }
    
    if(cmd->noCmd!=6){
        if(cmd->path2.inodeP<0){
            fprintf(stderr,"erreur path inexistant de Destination\n");
            return 0;
        }else{
            nom = cmd->path1.nom;
            if(cmd->path2.inodeE>0){
                ind = &tableauBloc[tabInode[cmd->path2.inodeE]].i;
                if(ind->type=='f'){
                    checkUpdate = updateInode(cmd->path2.inodeE, cmd->path1.inodeE,1);//1 ça veut dire inode deja existe
                    if (checkUpdate==-1) {
                        fprintf(stderr,"erreur d'espace memoire\n");
                    }
                    return 0;
                }else{ 
                    noInodeRDest = cmd->path2.inodeE;        
                }
                
            }else{
                if(validerNom(cmd->path2.nom)==-1){
                    fprintf(stderr,"erreur: nom\n");
                    return -1;
                }
                nom = cmd->path2.nom;
                noInodeRDest = cmd->path2.inodeP;
            }
            
            noInodeDest = premierInodeLibre();
            int noBlocLibre = allouerBlocLibres(); 
            if(noBlocLibre==-1){
                fprintf(stderr,"erreur: la memoir est plein\n");
                return -1;
            }
            tabInode[noInodeDest] = noBlocLibre;
            checkUpdate = updateInode(noInodeDest, cmd->path1.inodeE,0);// inode nouveau
            if (checkUpdate==-1) {
                fprintf(stderr,"erreur d'espace memoire\n");
                liberer(noBlocLibre);
                tabInode[noInodeDest] = -1;
                return 0;
            }
            if(cmd->noCmd!=6){
                int control = updateParent(noInodeRDest, noInodeDest, nom, -1, 1);//here si la memoire est pleine
                if(control==-1){
                    tabInode[noInodeDest]=-1;
                    liberer(noBlocLibre);
                    return 0;
                }
            }
        }
    }
    if(cmd->noCmd==6){// si c'est la commande rm
        cmd_rm(cmd->path1.inodeE);
    }
    if(cmd->noCmd==7 || cmd->noCmd==6){
        updateParent(cmd->path1.inodeP, -1, " ", cmd->path1.inodeE,0);
    }
    return 0;
}

int cmd_rm(int inode){ 
/* Elle efface un fichier en sepecifiant un numero d'inode.*/
    INODE *iInode = &tableauBloc[tabInode[inode]].i;
    if(iInode->type == 'f'){
        int nbBlocs;
        if(iInode->taille%2>0){
            nbBlocs = iInode->taille/2+1;
        }else{
            nbBlocs = iInode->taille/2;
        }
        libererSpace(nbBlocs, iInode);
        liberer(tabInode[inode]);
        tabInode[inode] = -1;
    }else{
        fprintf(stderr,"c'est un repertoir pas un fichier\n");
    }    
    return 0;
} 

int cmd_blc(struct Cmd *cmd){
/* Elle affiche les numeros de blocs utilisees par un fichier ou rep dont le nom est passe en parametre */
    int cnt = 0;// un compteur pour nbBloc afficher pour les ranger dans les ligne et colons
    if(cmd->path1.inodeE<0){
        fprintf(stderr,"le fichier %s n'existe pas\n", cmd->path1.nom);
        return 0;
    }
    INODE *inodeFichier = &tableauBloc[tabInode[cmd->path1.inodeE]].i;
    printf("%4d ",tabInode[cmd->path1.inodeE]);
    cnt++;
    int i = 0;
    while(i<10){
        if(inodeFichier->premiersBlocs[i]>0){
            printf("%4d ",inodeFichier->premiersBlocs[i] );
            cnt++;
        }
        if(cnt%15==0){
            printf("\n");
        }
        i++;   
    }
    if(inodeFichier->inSimple>0){
        printf("%4d ", inodeFichier->inSimple);
        cnt++;
        int j = 0;
        while(tableauBloc[inodeFichier->inSimple].inSIMPLE[j]> 0 && j<512){
	    if (j != 511){
                printf("%4d ",  tableauBloc[inodeFichier->inSimple].inSIMPLE[j]);
            cnt++;
            }
            j++;
            if(cnt%15==0){
                printf("\n");
            }
        }
    }
    if(inodeFichier->inDouble>0){
        printf("%4d ", inodeFichier->inDouble);
        cnt++;
        int i = 0;
        while(i<512 && tableauBloc[inodeFichier->inDouble].inSIMPLE[i]>0){     
            int j = 0;
            while(j<512 && tableauBloc [ tableauBloc[inodeFichier->inDouble].inSIMPLE[i]].inSIMPLE[j]>0){
                printf("%4d ",tableauBloc [ tableauBloc[inodeFichier->inDouble].inSIMPLE[i]].inSIMPLE[j]);
                cnt++;
                if(cnt%15==0){
                    printf("\n");
                }
                j++;
            }
            i++;
        }
    }
    if(cnt%15!=0){
        printf("\n");
    }
    return 0;  
}

int updateParent(int noInodeP, int noInode, char nom[129], int inode, int checkUpdate){//check update est 1 pour mkdir et crf
/* Elle ajoute l'noInode et le nom au parent ou noInode == inode dans l'inode de parent(noInodeP).*/
    if(retournNoInode(nom, noInodeP)>0 && checkUpdate==1){
        fprintf(stderr,"ce fichier deja existe dans le repertoir de destination\n");
        return -1;
    }else{
        INODE *inodeParent = &tableauBloc[tabInode[noInodeP]].i;
        int bool_ajoute = 0;
        int j = 0;
        while(bool_ajoute == 0 && j<10){
            int  i = 0;
            if (inodeParent->premiersBlocs[j]>-1) {
                while(bool_ajoute == 0 && i<15){
                    if(tableauBloc[inodeParent->premiersBlocs[j]].blocRep[i].noInode == inode){
                        //si le numero d'inode dans le parent est egal à inode donne (inode)
                        //on le met a jour par noInode et nom donnes
                        tableauBloc[inodeParent->premiersBlocs[j]].blocRep[i].noInode = noInode; 
                        strcpy(tableauBloc[inodeParent->premiersBlocs[j]].blocRep[i].nom , nom);
                        bool_ajoute = 1;
                    }
                    i++;
                }
            }else{
                int noBlocLibre = allouerBlocLibres(); 
                if(noBlocLibre==-1){//Bruno
                    fprintf(stderr,"erreur: la memoir est plein\n");
                    return -1;
                }
                inodeParent->premiersBlocs[j] = noBlocLibre;
                int l;
                for(l = 0; l<15; l++){/*elle initialize les restes d'inodes a -1*/
                    tableauBloc[inodeParent->premiersBlocs[j]].blocRep[l].noInode = -1;
                }
                tableauBloc[inodeParent->premiersBlocs[j]].blocRep[0].noInode = noInode; 
                strcpy(tableauBloc[inodeParent->premiersBlocs[j]].blocRep[i].nom , nom);
                bool_ajoute = 1;
            }
            j++;
        }
        if(bool_ajoute==0){
            printf("le repertoire est plein\n");
            return -1;
        }
    }    
    return 0;
}

int returnInodeParent(int noInode){
/* Elle retourne le numero d inode du parent *//* seulemnt pour les repertoirs */
    INODE *iInode = &tableauBloc[tabInode[noInode]].i;
    return tableauBloc[iInode->premiersBlocs[0]].blocRep[1].noInode;
}

int retournNoInode(char *nom , int noInodeP){
/* Elle retourne numero d'inode d'un fichier a partir de son nom et le numero d'inode 
 * de son parent et si il le trouve pas il retourne -1 */
    int noInode = -1;
    INODE *ind = &tableauBloc[tabInode[noInodeP]].i;
    int bool_ind_trouve = 0;
    int j=0;
    while(j<10 && bool_ind_trouve==0){
        if(ind->premiersBlocs[j]>-1){
            int k = 0;
            while(k<15 && bool_ind_trouve==0){ 
                if(strcmp(tableauBloc[ind->premiersBlocs[j]].blocRep[k].nom, nom)==0){   
                    bool_ind_trouve = 1;
                    noInode = tableauBloc[ind->premiersBlocs[j]].blocRep[k].noInode;
                }
                k++;
            }
        }
        j++;  
    }     
    return noInode;  
}

int updateInode(int noInodeDest, int noInodeSource, int identifierInode){
/*Elle met a jour l'inode du fichier destination a partir de inodeSource*/
    char timeString[40];
    recupererTemps(timeString, 40);
    int nbBlocDest; int nbBlocSource; int alloue;
    INODE *iDest = &tableauBloc[tabInode[noInodeDest]].i;
    INODE *iSource = &tableauBloc[tabInode[noInodeSource]].i;
    
    strcpy(iDest->mode, iSource->mode);
    iDest->UID = iSource->UID;
    iDest->GID = iSource->GID;
    iDest->type = iSource->type;
    strcpy(iDest->timeCreation,timeString);
    strcpy(iDest->timeAcces,timeString);
    strcpy(iDest->timeModification,timeString);
    if(identifierInode==0){
        int k;
        for (k=0; k<10; k++){
            iDest->premiersBlocs[k]=-1;
        }
        iDest->inSimple = -1;
        iDest->inDouble = -1;
        iDest->taille = iSource->taille;
        nbBlocDest = iSource->taille/2;
        if(iDest->taille%2!=0)    nbBlocDest++;
        alloue = allouerSpace(nbBlocDest, iDest);
        if(alloue!=0){
            libererSpace(alloue, iDest);
            return -1;
        }
    }
    
    // Si fichier dest deja existe on va seulement mettre a jour la taille
    if(identifierInode==1){
        nbBlocSource = iSource->taille/2;
        if(iSource->taille%2!=0)	nbBlocSource++;
        nbBlocDest = iDest->taille/2;
        if(iDest->taille%2!=0)	nbBlocDest++;
        int difNbBloc = nbBlocDest - nbBlocSource;
        /*Si la taille de deux fichier sont pas egales*/
        if(difNbBloc>0){
            libererSpace(difNbBloc, iDest);
        }else if(difNbBloc<0){
            alloue = allouerSpace(difNbBloc*(-1), iDest);
            if(alloue!=0){
                libererSpace(alloue, iDest);
                return -1;
            }
        }
        iDest->taille = iSource->taille;
    }
    
      return 0;
}

void recupererSousChaine(char * ptrBuffer, char * delimiteur, char ** tabSousChaine){
/* Elle reccoupere une chaine et la delimite par la chaine delimiteur et stocke le resultat 
 * dans tabSousChaine.*/
    int i;
    for(i=0; i<100; i++){
        tabSousChaine[i]=NULL;
    }
    char * ptrChaine;
    int indice = 0;

    ptrChaine = strtok(ptrBuffer, delimiteur);

    if(ptrChaine != NULL){
       tabSousChaine[indice] = ptrChaine;      
    }

    while(ptrChaine != NULL){
       ptrChaine = strtok(NULL, delimiteur);
       if(ptrChaine != NULL){
          ++indice;
          tabSousChaine[indice] = ptrChaine;   
       }
    }
 
}

int nbElement(char ** tabSousChaine){
/* Elle retourne le nombre d'elements contenu dans tabSousChaine*/
   int i = 0;
   while(tabSousChaine[i]!=NULL){
       i++;
   }
   return i;
}

int premierInodeLibre(){
/* Elle trouve premier inode libre(-1) dans le tabInode*/
    int i = 0;
    int bool_prB_trouve = 0;
    while(i<NB_MAX_INODE && bool_prB_trouve==0){
        if(tabInode[i]==-1){
     	    bool_prB_trouve=1;
        }
        i++;
    }
    return i-1;
} 

int allouerSpace(int nbBlocs, INODE *iInode){
/* Elle alloue space memoire à l'inode a partir de sa taille */
    int blocAlloue;
    int j = 0;
    int cntBlocAlloue = 0;
    while(j<10 && cntBlocAlloue<nbBlocs){
        if(iInode->premiersBlocs[j]<0){
            blocAlloue = allouerBlocLibres();
            if(blocAlloue!=-1){
                iInode->premiersBlocs[j] = blocAlloue;
                cntBlocAlloue++;
            }else{
                fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
                return cntBlocAlloue;
            }
        }
        j++;
    }
    
    if(cntBlocAlloue < nbBlocs){
        if(iInode->inSimple<1){
            blocAlloue = allouerBlocLibres();
            if(blocAlloue!=-1){
                iInode->inSimple = blocAlloue;
                int i;
                for (i=0; i<512; i++) {
                    tableauBloc[iInode->inSimple].inSIMPLE[i]=-1;
                }
                tableauBloc[iInode->inSimple].inSIMPLE[2]=-1;
                tableauBloc[iInode->inSimple].inSIMPLE[3]=-1;


            }else{
                fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
                return cntBlocAlloue;
            }
        }
        int k = 0;
        while(k<512 && cntBlocAlloue!=nbBlocs){
            if(tableauBloc[iInode->inSimple].inSIMPLE[k]<1){
                blocAlloue = allouerBlocLibres();
                if(blocAlloue!=-1){
                    tableauBloc[iInode->inSimple].inSIMPLE[k] = blocAlloue;
                    cntBlocAlloue++;
                }else{
                    fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
                    return cntBlocAlloue;
                }
            }
            k++;
        }
    }
    if(cntBlocAlloue < nbBlocs){
        if(iInode->inDouble<0){
            if(blocAlloue!=-1){
                iInode->inDouble = blocAlloue;
                int i;
                for (i=0; i<512; i++) {
                    tableauBloc[blocAlloue].inDOUBLE[i]=-1;
                }
            }else{
                fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
                return cntBlocAlloue;
            }

        }
        int k = 0;
        while(k<512 && cntBlocAlloue!=nbBlocs){  
            if (tableauBloc[iInode->inDouble].inDOUBLE[k]<0) {
              
                blocAlloue = allouerBlocLibres();
                if(blocAlloue!=-1){
                    tableauBloc[iInode->inDouble].inDOUBLE[k] = blocAlloue;
                    int i;
                    for (i=0; i<512; i++) {
                        tableauBloc[tableauBloc[iInode->inDouble].inDOUBLE[k]].inSIMPLE[i]=-1;
                    }
                    
                }else{
                    fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
                    return cntBlocAlloue;
                }
            }
            int j = 0;
            while(j<512 && cntBlocAlloue!=nbBlocs && tableauBloc[tableauBloc[iInode->inDouble].inDOUBLE[k]].inSIMPLE[j]<0){
                blocAlloue = allouerBlocLibres();
                if(blocAlloue!=-1){
                    tableauBloc[tableauBloc[iInode->inDouble].inDOUBLE[k]].inSIMPLE[j] = blocAlloue;
                    cntBlocAlloue++;
                }else{
                    fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
                    return cntBlocAlloue;
                }
                j++;
            }
            k++;
        }
    } 
    if (cntBlocAlloue < nbBlocs) {
        fprintf(stderr,"Impossible de creer un fichier avec la taille specifiee, espace disque insuffisant \n");
        return cntBlocAlloue;
    }
    return 0;
}

void liberer(int b){
    /*Elle met 0 pour le bit "b" dans la table blocLibres */
    //b: numero de bit a liberer
    int indice = b/32;//indice correspond a champ de tableau que le "b" se trouve de dans 
    int bits = b%32;//
    if((blocLibres[indice]& 1<<bits)){
        blocLibres[indice] &= ~(1<<bits); // met le bit a 0
    }
}

int allouerBlocLibres(){
    /*Elle alloue premier bloc disque ou le bit dans la table de blocLibres qui est egal a 0 */
    int cnt = 0;
    int i = 0;
    int bits = 0;
    int bool_bclLibre_trouve = 0;
    while((i+(120*cnt))<1920 && bool_bclLibre_trouve==0){
        if(blocLibres[i]!=0xFFFFFFFF){
            int b = 0;
            while(b<32 && bool_bclLibre_trouve==0){
                if((blocLibres[i]& 1<<b)==0){
                    blocLibres[i]|=1<<b;
                    bool_bclLibre_trouve=1;
                    bits = b;
                }
                b++;
            }
        }
        if((i+1)%120==0 && cnt<16){
            blocLibres = (unsigned int *)realloc(blocLibres,120*sizeof(unsigned int));
            cnt++;
            i=-1;
        }
        i++;
     }
    if (bool_bclLibre_trouve==0) {
        return -1;
    }
    int blocLibre= ((i-1)*32+(120*cnt))+bits;
    if (blocLibre > 61439 ) return -1;
    if (blocLibre >= nbBlocsAllouers) {
        tableauBloc =  (union blocDisque *) realloc(tableauBloc, sizeof (union blocDisque));//marche
        nbBlocsAllouers +=1;
    }  
    return blocLibre;
}

void libererSpace(int nbBlocs, INODE *iInode){
/* Elle trouve tous les blocs occupes pour l'inode "iInode" */
    int cntBlocLibrere = 0;
    
    if(iInode->inDouble>-1){
        int k = 511;
        while(k>=0 && cntBlocLibrere<nbBlocs){     
            int j = 511;
            if(tableauBloc[iInode->inDouble].inDOUBLE[k]>-1){
                while(j>=0 && cntBlocLibrere<nbBlocs){
                    if(tableauBloc[tableauBloc[iInode->inDouble].inDOUBLE[k]].inSIMPLE[j]>-1){
                        liberer(tableauBloc[tableauBloc[iInode->inDouble].inDOUBLE[k]].inSIMPLE[j]);
                        cntBlocLibrere++;
                    }
                    j--;
                }
            }
            k--;
        }
        iInode->inDouble = -1;
    }
    if(iInode->inSimple>-1){
        int i = 511;
        while(i>=0 && cntBlocLibrere<nbBlocs){
            if(tableauBloc[iInode->inSimple].inSIMPLE[i]>-1){
                liberer(tableauBloc[iInode->inSimple].inSIMPLE[i]);
                cntBlocLibrere++;
            }
            i--;
        }
        iInode->inSimple = -1;
    }
    int j = 9;
    while(j>=0 && cntBlocLibrere<nbBlocs){
        if(iInode->premiersBlocs[j]>0){
            liberer(iInode->premiersBlocs[j]);
            cntBlocLibrere++;
            iInode->premiersBlocs[j] = -1;
        }
        j--;
    }
}

int validerNom(char *nomDonne){
/* Elle valide si le nom commence pas par un signe ou .*/
    int i = 0;
    int size = (int)strlen(nomDonne);
    while(i<size){
        char ltr = nomDonne[i];
        if((ltr>47 && ltr<91 ) || (ltr> 96 && ltr<123)) {
            i++;   
        }else if((ltr == 46 && i!=0)){
            i++;
            
        }else{
            return -1;
        }
    }
    return 0;
}

void recupererTemps(char * timeString, int taille){
/* Elle obtient le temps actuel*/
   TEMPS * ptrTemps;
   time_t t2;
   char * format = "%Y-%m-%d %H:%M";
   time(&t2);
   ptrTemps = localtime ( &t2 );
   strftime(timeString, taille, format, ptrTemps);
}

int afficherPrompt(){
/* Elle affiche le prompt selon le repertoire courant "repCourant"*/
    char p = '#';
    char tmpNom[129] = "/";
    if(repCourant == 0){/* si le repertoire courant est la racine*/
        printf("%s%c ", tmpNom, p);
    }else{/* si repCourant !=0 */
        /* on cherche dans le parent de repertoir courant pour le nom de repertoire courant*/
        int noInodeP = returnInodeParent(repCourant);
        INODE *inodeP = &tableauBloc[tabInode[noInodeP]].i; 
        int bool_nom_trouve = 0;// 0 si le nom n'est pas trouve OU 1 si on le trouve dans le parent
        int i=0;
        while(i<10 && bool_nom_trouve == 0){
            int j=0;
            if(i==0){
                j=2;
            }
            if(inodeP->premiersBlocs[i]>-1){
                while(j<15 && bool_nom_trouve == 0){
                   if(tableauBloc[inodeP->premiersBlocs[i]].blocRep[j].noInode == repCourant){
                       strcpy(tmpNom,tableauBloc[inodeP->premiersBlocs[i]].blocRep[j].nom);
                       bool_nom_trouve = 1;
                   }
                   j++;
                }
            }
            i++;
        }
        if(noInodeP==0){/* si le parent est la racine on affiche le path au complet*/
            printf("/%s%c ", tmpNom, p);
        }else{/* on affiche seulement le nom de repertoir courant avec ~ pour les restes */
            printf("/~/%s%c ", tmpNom, p);
        }
    }
   return 0;
} 
