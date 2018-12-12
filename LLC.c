#include "LLC.h"

void Read_File(char *file_name)
{
    FILE *file = fopen(file_name, "r");
    unsigned char tramaAux[256];
    int c, flag = 0, tam_aux = 0;
    if (file == NULL)
        return;

    int count = 0;

    while ((c = fgetc(file)) != EOF)
    {
        if (flag)
        {
            if ((char)c == '}')
            {
                flag = 0;
                count++;
                printf("+---------------------------------------------+\n");
                printf(" Trama %d\n", count);
                printf("+---------------------------------------------+\n");
                imprimeTrama(tramaAux, ++tam_aux);
                printf("+---------------------------------------------+\n");
                tam_aux = 0;
                LLC_Analyser(tramaAux);
                memset(&tramaAux[0], 0, sizeof(tramaAux));
                continue;
            }
            if ((char)c != '\n')
            {
                char tmp;
                fscanf(file, "%hhx", &tramaAux[tam_aux++]);
            }
        }
        if ((char)c == '{')
            flag = 1;
    }
}

void imprimeTrama(unsigned char *trama, int tam)
{
    for (int i = 0; i < tam; i++)
    {
        if (i % 16 == 0 && i != 0)
            printf("\n");
        printf("%.2X ", trama[i]);
    }
    printf("\n");
}

void LLC_Analyser(unsigned char *trama)
{
    unsigned char MACOrigen[20], MACDestino[20];
    int tam = trama[12] + trama[13];
    int dsap = trama[14];
    int ssap = trama[15];
    int contr_1 = trama[16];
    int contr_2 = trama[17];

    sprintf(MACOrigen, "%02X:%02X:%02X:%02X:%02X:%02X", trama[0], trama[1], trama[2], trama[3], trama[4], trama[5]);
    sprintf(MACDestino, "%02X:%02X:%02X:%02X:%02X:%02X", trama[6], trama[7], trama[8], trama[9], trama[10], trama[11]);
    printf(" MAC Origen:\t%s\n MAC Destino:\t%s\n Longitud:\t%d\n", MACOrigen, MACDestino, tam);

    DSAP_Analyser(dsap);
    SSAP_Analyser(ssap);
    Control(contr_1, contr_2);
    printf("\n");
}

void DSAP_Analyser(int dsap)
{
    char bits_dsap[8], bits_ssap[8];
    Int_to_Binary_String(bits_dsap, dsap);
    memcpy(bits_ssap, bits_dsap, 7);
    bits_ssap[7] = 0;
    printf(" DSAP:\t\t");
    SAP_Switch(Binary_String_to_Int(bits_ssap));
    printf(bits_dsap[7] == 0 ? "\t| Individual\n" : "\t| Grupal\n");
}

void SSAP_Analyser(int ssap)
{
    char bits_ssap[8], ssapBinario[8];
    Int_to_Binary_String(ssapBinario, ssap);
    memcpy(bits_ssap, ssapBinario, 7);
    bits_ssap[7] = 0; //Completado de cadena
    printf(" SSAP:\t\t");
    SAP_Switch(Binary_String_to_Int(bits_ssap));
    printf(ssapBinario[7] == 0 ? "\t| Comando\n" : "\t| Respuesta\n");
}

int Binary_String_to_Int(char *cadena)
{
    int multiplier = 0, total = 0;
    for (int i = 7; i >= 0; i--)
        total += pow(2, multiplier++) * cadena[i];
    return total;
}

void SAP_Switch(int n)
{
    switch (n)
    {
    case 0x00:
        printf("Null LSAP");
        break;
    case 0x02:
        printf("Individual LLC Sublayer Management Function");
        break;
    case 0x03:
        printf("Group LLC Sublayer Management Function");
        break;
    case 0x04:
        printf("IBM SNA Path Control (individual)");
        break;
    case 0x05:
        printf("IBM SNA Path Control (group)");
        break;
    case 0x06:
        printf("ARPANET Internet Protocol (IP)");
        break;
    case 0x08:
    case 0x34:
    case 0x0C:
        printf("SNA");
        break;
    case 0x0E:
        printf("PROWAY (IEC955) Network Management & Initialization");
        break;
    case 0x18:
        printf("Texas Instruments");
        break;
    case 0x42:
        printf("IEEE 802.1 Bridge Spanning Tree Protocol");
        break;
    case 0x72:
        printf("ISO 8208 (X.25 over IEEE 802.2 Type 2 LLC)");
        break;
    case 0x80:
        printf("Xerox Network Systems (XNS)");
        break;
    case 0x86:
        printf("Nestar");
        break;
    case 0x82:
        printf("PROWAY (IEC 955) Active Station List Maintenance");
        break;
    case 0x98:
        printf("ARPANET Address Resolution Protocol (ARP)");
        break;
    case 0xBC:
        printf("Banyan VINES");
        break;
    case 0xAA:
        printf("SubNetwork Access Protocol (SNAP)");
        break;
    case 0xE0:
        printf("Novell NetWare");
        break;
    case 0xF0:
        printf("IBM NetBIOS");
        break;
    case 0xF4:
        printf("IBM LAN Management (individual)");
        break;
    case 0xF5:
        printf("IBM LAN Management (group)");
        break;
    case 0xF8:
        printf("IBM Remote Program Load (RPL)");
        break;
    case 0xFA:
        printf("Ungermann-Bass");
        break;
    case 0xFE:
        printf("ISO Network Layer Protocol");
        break;
    case 0xFF:
        printf("Global LSAP");
        break;
    default:
        printf("Yikes!");
        break;
    }
}

void Control(int byte_1, int byte_2)
{
    char bits_contr_1[8], bits_contr_2[8];
    Int_to_Binary_String(bits_contr_1, byte_1);
    Int_to_Binary_String(bits_contr_2, byte_2);
    printf(" Control:\t");
    if (bits_contr_1[7] == 0)
    {
        printf("Trama de información");
        char bits_aux[8];
        memcpy(bits_aux, bits_contr_1, 7);
        bits_aux[7] = 0;
        printf("\tN(Send): %d", Binary_String_to_Int(bits_aux));
        memcpy(bits_aux, bits_contr_2, 7);
        bits_aux[7] = 0;
        printf("\n\t\tN(Recived): %d", Binary_String_to_Int(bits_aux));
        printf(bits_contr_2[7] == 0 ? "\tComando" : "\tRespuesta");
    }
    else if (bits_contr_1[6] == 0 && bits_contr_1[7] == 1)
    {
        printf("Trama de supervision");
        if (bits_contr_1[4] == 0 && bits_contr_1[5] == 0)
            printf("\tReceiver Ready");
        else if (bits_contr_1[4] == 0 && bits_contr_1[5] == 1)
            printf("\tReceiver Not Ready");
        else
            printf("\tReject");
        char bits_aux[8];
        memcpy(bits_aux, bits_contr_2, 7);
        bits_aux[7] = 0;
        printf("\n\t\tN(Recived): %d", Binary_String_to_Int(bits_aux));
        printf(bits_contr_2[7] == 0 ? "\tComando\n" : "\tRespuesta");
    }

    else
    { //Trama no numerada
        printf("Trama no numerada");
        if (bits_contr_1[0] == 0 && bits_contr_1[1] == 0 &&
            bits_contr_1[2] == 0 && bits_contr_1[4] == 1 && bits_contr_1[5] == 1)
        {
            printf("Disconnect Mode (DM)");
        }
        else if (bits_contr_1[0] == 0 && bits_contr_1[1] == 1 &&
                 bits_contr_1[2] == 0 && bits_contr_1[4] == 0 && bits_contr_1[5] == 0)
        {
            printf("Disconnect (DISC)");
        }
        else if (bits_contr_1[0] == 0 && bits_contr_1[1] == 1 &&
                 bits_contr_1[2] == 1 && bits_contr_1[4] == 0 && bits_contr_1[5] == 0)
        {
            printf("Unnumbered Acknowledgment (UA)");
        }
        else if (bits_contr_1[0] == 0 && bits_contr_1[1] == 1 &&
                 bits_contr_1[2] == 1 && bits_contr_1[4] == 1 && bits_contr_1[5] == 1)
        {
            printf("Set Asynchronous Balanced Mode (SABME)");
        }
        else if (bits_contr_1[0] == 1 && bits_contr_1[1] == 0 &&
                 bits_contr_1[2] == 0 && bits_contr_1[4] == 0 && bits_contr_1[5] == 1)
        {
            printf("Frame Reject (FRMR)");
        }
        else if (bits_contr_1[0] == 1 && bits_contr_1[1] == 0 &&
                 bits_contr_1[2] == 1 && bits_contr_1[4] == 1 && bits_contr_1[5] == 1)
        {
            printf("Exchange Id (XID)");
        }
        else if (bits_contr_1[0] == 1 && bits_contr_1[1] == 1 &&
                 bits_contr_1[2] == 1 && bits_contr_1[4] == 0 && bits_contr_1[5] == 0)
        {
            printf("Test (TEST)");
        }
        printf((bits_contr_1[3] == 0) ? " Comando" : " Respuesta");
    }
}

void Int_to_Binary_String(char *buffer, int num)
{
    for (int i = 0, j = 7; i < 8; i++, j--)
        buffer[j] = (num >> i) & 1; //Loop para obtener el bit en posición "i"
}