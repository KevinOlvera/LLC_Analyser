#include "tramas.h"

int GetData(unsigned char trama[]);
int IP(char T[]);
void checksum(unsigned char T[],unsigned char tam,unsigned char haha,unsigned char jaja);
void ICMP(unsigned  char tam,char T[]);
void TCP(unsigned char tam,unsigned char T[]);
void UDP(unsigned char tam,unsigned char T[],unsigned char opc);

int main(int argc,char**argv)
{


  for(unsigned char i=0,j=31;i<16;i++,j++)
  {
    if(GetData(frameF(i))==1)
    {
     //printf("\033[1;%dm",j);
      if(j==36)
        j=30;
      if(i+1<10)
      {
        printf("\t*----------------------------------------------*\n");
        printf("\t| Trama :  %i                                   |\n",i+1);
        printf("\t| %s\n",result);
      }
    
    }
    strcpy(result," ");
}

  return 0;
}


int GetData(unsigned char T[])
{
  unsigned short int ToT=(T[12]<<8)+T[13];

  if(ToT<1500)
  {
    switch(T[16]&3)
    {
      case 0:

      sprintf(result+strlen(result),"T-I N(s) = %d, N(r) = %d",T[16]>>1,T[17]>>1);
      break;

      case 2:

      sprintf(result+strlen(result),"T-I N(s) = %d, N(r) = %d",T[16]>>1,T[17]>>1);
      break;

      case 1:

      sprintf(result+strlen(result),"T-S     %s  ",supervision[(T[16]>>2)&3]);
      break;

      case 3:
      if((T[16]>>4)&1)
      {
        if(T[15]&1)
        sprintf(result+strlen(result),"T-U   %s  ",ur[((T[16]>>2)&3)+(((T[16]>>3)&28))]);
        else
        sprintf(result+strlen(result),"T-U  %s  ",uc[((T[16]>>2)&3)+(((T[16]>>3)&28))]);
      }
      else
      {
        sprintf(result+strlen(result),"T-U");
      }

      break;
    }
    return 1;
  }
  else if(ToT==2054)
  {
    switch((T[14]<<8)+T[15])
    {
      case 0x0001:
      sprintf(result+strlen(result),"Hw type: %s\n",hardware[0]);
      break;

      case 0x0006:
      sprintf(result+strlen(result),"Hw type: %s\n",hardware[1]);
      break;

      case 0x000F:
      sprintf(result+strlen(result),"Hw type: %s\n",hardware[2]);
      break;

      case 0x0010:
      sprintf(result+strlen(result),"Hw type: %s\n",hardware[3]);
      break;

      default:
      sprintf(result+strlen(result),"\tTrama dañada\n");
      break;
    }

    if(((T[16]<<8)+T[17])==0x0800)
      sprintf(result+strlen(result),"\t|Protocol type: IP\n");
    else
      sprintf(result+strlen(result),"\t|Trama dañada\n");

    unsigned char HwL,PaL;
    HwL=T[18];
    PaL=T[19];

    switch((T[20]<<8)+T[21])
    {
      case 1:
       sprintf(result+strlen(result),"\t|Operation Code: ARP request\n");
      break;

      case 2:
       sprintf(result+strlen(result),"\t|Operation Code: ARP reply\n");
      break;

      case 8:
        sprintf(result+strlen(result),"\t|Operation Code: Inverse ARP request\n");
      break;

      case 9:
       sprintf(result+strlen(result),"\t|Operation Code: Inverse ARP Reply\n");
      break;

      default:
       sprintf(result+strlen(result),"\t|Trama dañada\n");
      break;
    }

    sprintf(result+strlen(result),"\t|Sender HW address: ");
    unsigned char aux=22;

    for(int i=0;i<HwL;i++)
      sprintf(result+strlen(result),"%02x:",T[aux++]);
    sprintf(result+strlen(result),"\n");

    sprintf(result+strlen(result),"\t|Sender Protocol address: ");
    for(int i=0;i<PaL;i++)
      sprintf(result+strlen(result),"%d.",T[aux++]);
    sprintf(result+strlen(result),"\n");

    sprintf(result+strlen(result),"\t|Target Hardware address: ");
    for(int i=0;i<HwL;i++)
      sprintf(result+strlen(result),"%02x:",T[aux++]);
    sprintf(result+strlen(result),"\n");

    sprintf(result+strlen(result),"\t|Target Protocol address: ");
    for(int i=0;i<PaL;i++)
      sprintf(result+strlen(result),"%d.",T[aux++]);
    sprintf(result+strlen(result),"\n");

      return 1;
  }
  else if(ToT==0x0800)
  {
    sprintf(result+strlen(result),"Es de Ip\n");
    return IP(T);
  }
  else
  return 0;
}


int IP(char T[])
{
  /*Empieza desdde la posicion 14*/
  sprintf(result+strlen(result),"\t|Ip version: %d\n",(T[14]>>4));

  unsigned char ihl=(T[14]&15)*4;

  sprintf(result+strlen(result),"\t|IHL: %d bytes\n",ihl);

  sprintf(result+strlen(result),"\t|Tipo de servicio: ");
  if((T[15]&16)==0)
  sprintf(result+strlen(result),"\tPrioritario");
  else if((T[15]&16)==2)
  sprintf(result+strlen(result),"\tRetardo");
  else if((T[15]&16)==4)
  sprintf(result+strlen(result),"\tRendimiento");
  else if((T[15]&16)==8)
  sprintf(result+strlen(result),"\tConfiable");
  else if((T[15]&16)==16)
  sprintf(result+strlen(result),"\tCosto");
  else if((T[15]&32)>16)
  sprintf(result+strlen(result),"\tTrama dañada");

  unsigned  short a= ((T[16]<<8)+T[17]);
  sprintf(result+strlen(result),"\n\t|Tamaño del paquete: %d",a);

  a=(T[18]<<8)+T[19];
  sprintf(result+strlen(result),"\n\t|Identificador: %d",a);

  sprintf(result+strlen(result),"\n\t|Banderas: ");

  if(T[20]&64)
  {
    if(T[20]&32)
      sprintf(result+strlen(result),"### ERROR");
    sprintf(result+strlen(result),"Dont fragment  ");
  }
  else
    sprintf(result+strlen(result),"Fragment  ");

  if(T[20]&32)
    sprintf(result+strlen(result),"-> More Fragments");
  else
    sprintf(result+strlen(result),"-> Last Fragment");

  a=((T[20]&31)<<8)+T[21];
  sprintf(result+strlen(result),"\n\t|Offset: %d",a);

  unsigned char b=T[22];
  sprintf(result+strlen(result),"\n\t|Numero de saltos: %d",b);

  sprintf(result+strlen(result),"\n\t|Protocolo: ");
  if((T[23]&31)==1)
    sprintf(result+strlen(result),"  ICMP");
  else if((T[23]&31)==6)
    sprintf(result+strlen(result),"  TCP");
  else if((T[23]&31)==17)
    sprintf(result+strlen(result),"  UDP");

  unsigned char chsum_c=T[25], chsum_t=T[24];
  sprintf(result+strlen(result),"\n\t|Checksum teorico:  %02x %02x \n\t|Checksum Calculado: ", chsum_t, chsum_c);
  checksum(T, ihl, chsum_t, chsum_c);


  sprintf(result+strlen(result),"\n\t|Ip de origen: ");
  for(unsigned char i=26;i<30;i++)
  {
    b=T[i];
    sprintf(result+strlen(result),"%d.",b);
  }

  sprintf(result+strlen(result),"\n\t|Ip de destino: ");
  for(unsigned char i=30;i<34;i++)
  {
    b=T[i];
    sprintf(result+strlen(result),"%d.",b);
  }

  sprintf(result+strlen(result),"\n\t|Opciones: ");
  for(unsigned char i=34;i<ihl+14;i++)
  {
    b=T[i];
    sprintf(result+strlen(result),"%x ",b);
  }

  if((T[23]&31)==1)
    ICMP(ihl+14,T);
  if((T[23]&31)==6)
    TCP(ihl+14,T);
  if((T[23]&31)==17)
    UDP(ihl+14,T,T[14]&15);
  return 1;
}

void ICMP(unsigned  char tam,char T[])
{
  sprintf(result+strlen(result),"\n\t|Tipo:  ");
  switch(T[tam])
  {
    case 0:
    sprintf(result+strlen(result),"Echo reply\n");
    break;

    case 3:
    sprintf(result+strlen(result),"Destination unreachable -->   ");
    switch (T[tam+1])
    {
      case 0:
      sprintf(result+strlen(result),"Net unreachable\n");
      break;

      case 1:
      sprintf(result+strlen(result),"Host unreachable\n");
      break;

      case 2:
      sprintf(result+strlen(result),"Protocol unreachable\n");
      break;

      case 3:
      sprintf(result+strlen(result),"Port unreachable\n");
      break;

      case 4:
      sprintf(result+strlen(result),"Fragmentation needed & df set\n");
      break;

      case 5:
      sprintf(result+strlen(result),"Source route failed\n");
      break;

      case 6:
      sprintf(result+strlen(result),"Destination network unknown\n");
      break;

      case 7:
      sprintf(result+strlen(result),"Destination host unknown\n");
      break;

      case 8:
      sprintf(result+strlen(result),"Source host isolated\n");
      break;

      case 9:
      sprintf(result+strlen(result),"Network administratively prohibed\n");
      break;

      case 10:
      sprintf(result+strlen(result),"Host administratively prohibed\n");
      break;

      case 11:
      sprintf(result+strlen(result),"Network unreachable for TOS\n");
      break;

      case 12:
      sprintf(result+strlen(result),"Host unreachable for TOS\n");
      break;

      case 13:
      sprintf(result+strlen(result),"Comunication administratively prohibed\n");
      break;
    }
    break;

    case 4:
    sprintf(result+strlen(result),"Source Quench\n");
    break;

    case 5:
    sprintf(result+strlen(result),"Redirect\n");
    break;

    case 8:
    sprintf(result+strlen(result),"Echo\n");
    break;

    case 9:
    sprintf(result+strlen(result),"Router Advertisment\n");
    break;

    case 10:
    sprintf(result+strlen(result),"Router Selection\n");
    break;

    case 11:
    sprintf(result+strlen(result),"Time exceded\n");
    break;

    case 12:
    sprintf(result+strlen(result),"Parameter problem\n");
    break;

    case 13:
    sprintf(result+strlen(result),"Timestamp\n");
    break;

    case 14:
    sprintf(result+strlen(result),"Timestamp reply\n");
    break;

    case 15:
    sprintf(result+strlen(result),"Information request\n");
    break;

    case 16:
    sprintf(result+strlen(result),"Information reply\n");
    break;

    case 17:
    sprintf(result+strlen(result),"Address mask request\n");
    break;

    case 18:
    sprintf(result+strlen(result),"Address mask reply\n");
    break;

    case 30:
    sprintf(result+strlen(result),"Tracarouta\n");
    break;
  }
  
  sprintf(result+strlen(result),"\t|Checksum:  %02x %02x",T[tam+2],T[tam+3]);
  
  unsigned char *ptr=T;
  
  for(int i=0;i<=tam+7;ptr++,i++);
  
  sprintf(result+strlen(result),"\n\t|Datos: ");

  for(;*ptr!='\0';ptr++)
    sprintf(result+strlen(result),"%c ",*ptr);
}


void TCP(unsigned char tam,unsigned char T[])
{

    if(T[tam+14]&32)
    {
      sprintf(result+strlen(result),"\n\t|Trama urgente :): ");
      sprintf(result+strlen(result),"\n\t|MAc destino: ");
      for(int i=0;i<4;i++)
        sprintf(result+strlen(result),"%02x:",T[i]);
      sprintf(result+strlen(result),"\n\n");
    }

    if((T[tam+12]>>4)>5)
    {
      sprintf(result+strlen(result),"\n\t|Opciones TCP: ");
      for(int i=tam+20;i<(T[tam+12]>>4)*4+tam;i++)
        sprintf(result+strlen(result),"%02x ",T[i]);
    }
}

void UDP(unsigned char tam,unsigned char T[],unsigned char opc)
{
  if(opc<=5)
  {
    sprintf(result+strlen(result),"\n\t|Checksum: %02x  %02x",T[tam+6],T[tam+7]);
  }
}

void checksum(unsigned char T[],unsigned char tam,unsigned char haha,unsigned char jaja)
{
  short aux=0;
  unsigned char par,impar;
  for(int i=14;i<tam+14;i++)
  {

    if(i==24)
    {
      i+=1;
      continue;
    }
    if((i%2)==0)
    {
      aux+=T[i];
    }

  }
  impar=aux>>8;
  par=aux;
  aux=0;
  for(int i=14;i<tam+14;i++)
  {

    if(i==25)
    {
      i+=1;
      continue;
    }
    if((i%2)==1)
    {
      aux+=T[i];
    }

  }

  par+=aux>>8;
  impar+=aux;

  impar=~impar;
  par=~par;
  sprintf(result+strlen(result),"  %02x  %02x ",par,impar);
  if(par==haha && impar==jaja)
  sprintf(result+strlen(result),"\n\t|Checksum correcto");
}
