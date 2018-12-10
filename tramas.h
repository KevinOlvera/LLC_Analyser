#include <stdio.h>

char* frame(int i);

/*
unsigned char T[ ][43]={
{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x03,0xf0,0xf0,
0x7f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 1

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x03,0xf0,0xf1,
0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 2

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x04,0xf0,0xf0,
0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},//Trama 3

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 4

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x12,0xf0,0xf0,
0x00,0x01,0x0e,0x00,0xff,0xef,0x19,0x8f,0xbc,0x05,0x7f,0x00,0x23,0x00,0x7f,0x23}, //Trama 5

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x12,0xf0,0xf0,
0x00,0x03,0x0e,0x00,0xff,0xef,0x19,0x8f,0xbc,0x05,0x7f,0x00,0x23,0x00,0x7f,0x23}, //Trama 6

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 7

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 8

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0xac,0xf0,0xf0,
0x02,0x02,0x0e,0x00,0xff,0xef,0x16,0x04,0x00,0x00,0x00,0x00,0x28,0x00,0x7f,0x23}, //Trama 9

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 10

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x5f,0xf0,0xf0,
0x02,0x04,0x0e,0x00,0xff,0xef,0x16,0x0c,0x00,0x00,0x28,0x00,0x28,0x00,0x7f,0x23}, //Trama 11

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x04,0xf0,0xf1,
0x01,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 12

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x91,0xf0,0xf0,
0x04,0x04,0x0e,0x00,0xff,0xef,0x16,0x0c,0x00,0x00,0x28,0x00,0x28,0x00,0x7f,0x23}, //Trama 13

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 14

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x46,0xf0,0xf0,
0x04,0x06,0x0e,0x00,0xff,0xef,0x16,0x0c,0x00,0x00,0x28,0x00,0x28,0x00,0x7f,0x23}, //Trama 15

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x04,0xf0,0xf1,
0x01,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 16

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x7e,0xf0,0xf0,
0x06,0x06,0x0e,0x00,0xff,0xef,0x16,0x0c,0x00,0x00,0x28,0x00,0x28,0x00,0x7f,0x23}, //Trama 17

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 18

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x04,0xf0,0xf1,
0x01,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 19

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x7e,0xf0,0xf0,
0x08,0x08,0x0e,0x00,0xff,0xef,0x16,0x0c,0x00,0x00,0x28,0x00,0x28,0x00,0x7f,0x23}, //Trama 20

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 21

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x04,0xf0,0xf1,
0x01,0x0a,0x0e,0x00,0xff,0xef,0x19,0x8f,0xbc,0x05,0x7f,0x00,0x23,0x00,0x7f,0x23}, //Trama 22

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x12,0xf0,0xf0,
0x0a,0x0b,0x0e,0x00,0xff,0xef,0x14,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x7f,0x23}, //Trama 23

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x0d,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 24

{0x03,0x00,0x00,0x00,0x00,0x01,0x00,0x04,0xac,0x44,0x4d,0x02,0x00,0x8b,0xf0,0xf0,
0x03,0x2c,0x00,0xff,0xef,0x08,0x00,0x00,0x00,0x00,0x00,0x28,0x00,0x42,0x34,0x20}, //Trama 25

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x35,0xf0,0xf0,
0x0c,0x0a,0x0e,0x00,0xff,0xef,0x16,0x04,0x00,0x00,0x00,0x00,0x28,0x00,0x7f,0x23}, //Trama 26

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x35,0xf0,0xf0,
0x0a,0x0e,0x00,0x00,0xff,0xef,0x16,0x04,0x00,0x00,0x00,0x00,0x28,0x00,0x7f,0x23}, //Trama 27

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x12,0xf0,0xf0,
0x0e,0x0d,0x0e,0x00,0xff,0xef,0x14,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x7f,0x23}, //Trama 28

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x11,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 29

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x12,0xf0,0xf0,
0x10,0x0d,0x0e,0x00,0xff,0xef,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x23}, //Trama 30

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x04,0xf0,0xf1,
0x01,0x13,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 31

{0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x03,0xf0,0xf0,
0x53,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, //Trama 32

{0x00,0x02,0xb3,0x9c,0xdf,0x1b,0x00,0x02,0xb3,0x9c,0xae,0xba,0x00,0x03,0xf0,0xf1,
0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},//Trama 33

{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x23,0x8B,0x46,0xE9,0xAD,0x08,0x06,0x00,0x01,
 0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x23,0x8B,0x46,0xE9,0xAD,0x94,0xCC,0x39,0xCB,
 0x00,0x00,0x00,0x00,0x00,0x00,0x94,0xCC,0x39,0xFE}
 }; //Trama34
*/


unsigned char trama[21][125]={
/* TRAMA 1 */
{
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x23, /* .......# */
0x8b, 0x46, 0xe9, 0xad, 0x08, 0x06, 0x00, 0x04, /* .F...... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x23, /* .......# */
0x8b, 0x46, 0xe9, 0xad, 0x94, 0xcc, 0x39, 0xcb, /* .F....9. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xcc, /* ........ */
0x39, 0xfe                                      /* 9. */
},

/*TRAMA 2 */
{
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, /* .#.F.... */
0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x06, 0x00, 0x01, /* E....... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x1f, /* ........ */
0x45, 0x9d, 0x1e, 0xa2, 0x94, 0xcc, 0x39, 0xfe, /* E.....9. */
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x94, 0xcc, /* .#.F.... */
0x39, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 9....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
},

/* TRAMA 3 */
{
0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, /* ..E....# */
0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x46, 0x00, /* .F....F. */
0x80, 0x42, 0x04, 0x55, 0x34, 0x11, 0x80, 0x11, /* .B.U4... */
0x6b, 0xf0, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, /* k...9... */
0x67, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x04, 0x0c, /* g....... */
0x00, 0x35, 0x00, 0x2e, 0x85, 0x7c, 0xe2, 0x1a, /* .5...|.. */
0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69, /* ...www.i */
0x73, 0x63, 0x05, 0x65, 0x73, 0x63, 0x6f, 0x6d, /* sc.escom */
0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00, /* .ipn.mx. */
0x00, 0x1c, 0x00, 0x01                          /* .... */
},

/* TRAMA 4 */
{
0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x02, /* ........ */
0xb3, 0x9c, 0xae, 0xba, 0x00, 0x04, 0xf0, 0xf0, /* ........ */
0x01, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x9b, 0x6d  /* .....|.m */
},

/* TRAMA 5 */
{
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x23, /* .......# */
0x8b, 0x46, 0xe9, 0xad, 0x08, 0x06, 0x00, 0x10, /* .F...... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x03, 0x00, 0x23, /* .......# */
0x8b, 0x46, 0xe9, 0xad, 0x94, 0xcc, 0x39, 0xcb, /* .F....9. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xcc, /* ........ */
0x3a, 0xe1                                      /* :. */
},

/* TRAMA 6*/
{
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, /* .#.F.... */
0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x06, 0x00, 0x10, /* E....... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x04, 0x00, 0x1f, /* ........ */
0x45, 0x9d, 0x1e, 0xa2, 0x94, 0xcc, 0x3a, 0xe1, /* E.....:. */
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x94, 0xcc, /* .#.F.... */
0x39, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 9....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
},

/* TRAMA 7 */
{
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, /* .#.F.... */
0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x00, 0x45, 0x00, /* E.....E. */
0x00, 0x6f, 0x90, 0x30, 0x40, 0x00, 0xfb, 0x11, /* .o.0@... */
0x24, 0xe7, 0x94, 0xcc, 0x67, 0x02, 0x94, 0xcc, /* $...g... */
0x39, 0xcb, 0x00, 0x35, 0x04, 0x0c, 0x00, 0x5b, /* 9..5...[ */
0xe8, 0x60, 0xe2, 0x1a, 0x85, 0x80, 0x00, 0x01, /* .`...... */
0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x77, /* .......w */
0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65, /* ww.isc.e */
0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, /* scom.ipn */
0x02, 0x6d, 0x78, 0x00, 0x00, 0x1c, 0x00, 0x01, /* .mx..... */
0xc0, 0x14, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x0e, 0x10, 0x00, 0x21, 0x04, 0x64, 0x6e, 0x73, /* ...!.dns */
0x31, 0xc0, 0x1a, 0x03, 0x74, 0x69, 0x63, 0xc0, /* 1...tic. */
0x1a, 0x77, 0xec, 0xdf, 0x29, 0x00, 0x00, 0x2a, /* .w..)..* */
0x30, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, /* 0......u */
0x00, 0x00, 0x00, 0x2a, 0x30                    /* ...*0 */
},

/* TRAMA 8 */
{
0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, /* ..E....# */
0x02, 0x03, 0x04, 0x05, 0x08, 0x00, 0x45, 0x00, /* .F....E. */
0x00, 0x42, 0x04, 0x56, 0x00, 0x00, 0x80, 0x11, /* .B.V.... */
0x6b, 0xef, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, /* k...9... */
0x67, 0x02, 0x04, 0x0c, 0x00, 0x35, 0x00, 0x2e, /* g....5.. */
0xff, 0x87, 0x68, 0x2a, 0x01, 0x00, 0x00, 0x01, /* ..h*.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, /* .......w */
0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65, /* ww.isc.e */
0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, /* scom.ipn */
0x02, 0x6d, 0x78, 0x00, 0x00, 0x01, 0x00, 0x01  /* .mx..... */
},

/* TRAMA 9 */
{
0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, /* ..E....# */
0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x45, 0x00, /* .F....E. */
0x00, 0x3c, 0x04, 0x57, 0x00, 0x00, 0x80, 0x01, /* .<.W.... */
0x98, 0x25, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, /* .%..9... */
0x3a, 0xe1, 0x08, 0x00, 0x49, 0x5c, 0x03, 0x00, /* :...I\.. */
0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
},

/* TRAMA 10 */
{
0x00, 0x02, 0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x02, /* ........ */
0x02, 0x03, 0x04, 0x05, 0x00, 0x04, 0xf0, 0xf0, /* ........ */
0x0c, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x9b, 0x6d  /* .....|.m */
},

/* trama 11 */
{
0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x11, 0x11, /* ........ */
0x11, 0x11, 0x11, 0x11, 0x00, 0x03, 0xf0, 0xf0, /* ........ */
0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x43, 0x05, 0x90, 0x6d  /* ....C..m */
},

/* trama 12 */
{
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, /* .#.F.... */
0x02, 0x03, 0x04, 0x05, 0x08, 0x00, 0x45, 0x00, /* E.....E. */
0x00, 0x3c, 0x01, 0xb5, 0x00, 0x00, 0x3f, 0x01, /* .<....?. */
0xdb, 0xc7, 0x94, 0xcc, 0x3a, 0xe1, 0x94, 0xcc, /* ....:... */
0x39, 0xcb, 0x00, 0x00, 0x51, 0x5c, 0x03, 0x00, /* 9...Q\.. */
0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
},

/* trama 13 */
{
0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x01, /* ........ */
0x02, 0x03, 0x04, 0x05, 0x00, 0x03, 0xf0, 0xf1, /* ........ */
0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x43, 0x05, 0x90, 0x6d  /* ....C..m */
},

/* trama 14 */
{
0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x1c, /* ..E..... */
0xc0, 0x7b, 0x35, 0xa1, 0x08, 0x00, 0x48, 0x00, /* .{5...H. */
0x00, 0x48, 0x5c, 0x7d, 0x00, 0x00, 0x80, 0x01, /* .H\}.... */
0x6c, 0x88, 0x94, 0xcc, 0x39, 0xc3, 0x94, 0xcc, /* l...9... */
0x00, 0x49, 0x07, 0x0b, 0x04, 0x00, 0x00, 0x00, /* .I...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, /* ........ */
0x3b, 0x5c, 0x02, 0x00, 0x10, 0x00, 0x61, 0x62, /* ;\....ab */
0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, /* cdefghij */
0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, /* klmnopqr */
0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, /* stuvwabc */
0x64, 0x65, 0x66, 0x67, 0x68, 0x69              /* defghi */
},

/* trama 15*/
{
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, /* .#.F.... */
0x45, 0x9d, 0x1e, 0xa2, 0x80, 0x35, 0x00, 0x01, /* E....5.. */
0x08, 0x00, 0x06, 0x04, 0x00, 0x03, 0x00, 0x1f, /* ........ */
0x45, 0x9d, 0x1e, 0xa2, 0x94, 0xcc, 0x3a, 0xe1, /* E.....:. */
0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x94, 0xcc, /* .#.F.... */
0x39, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 9....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0xd8, 0xee, 0xdf, 0xb0  /* ........ */
},

/* trama 16 */
{
0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x22, 0x22, /* ........ */
0x22, 0x22, 0x22, 0x22, 0x00, 0x03, 0xf0, 0xf0, /* ........ */
0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x43, 0x05, 0x90, 0x6d  /* ....C..m */
},

/*trama 17 */
{
0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x02, /* ........ */
0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x03, 0xf0, 0xf0, /* ........ */
0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x43, 0x05, 0x90, 0x6d  /* ....C..m */
},

/* trama 18 */
{
0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, /* ..S..... */
0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00, /* f..<..E. */
0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, /* .0,.@... */
0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, /* Kt...... */
0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, /* .......; */
0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x70, 0x20, /* .D....p  */
0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, /*  ..4.... */
0x05, 0xb4, 0x01, 0x01, 0x04, 0x02              /* ...... */
},

/*trama 19 */
{
0x00, 0x02, 0xb3, 0x9c, 0xae, 0xba, 0x00, 0x02, /* ........ */
0xb3, 0x9c, 0xdf, 0x1b, 0x00, 0x03, 0xf0, 0xf1, /* ........ */
0x53, 0x0b, 0x0e, 0x00, 0xff, 0xef, 0x14, 0x00, /* ........ */
0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x7f, 0x23, /* ..(....# */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x01, 0x99, 0x98, 0x6d  /* .......m */
},
/* trama 20 */
{
0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x02, 0xff, /* ..f..<.. */
0x53, 0xc3, 0xe9, 0xab, 0x08, 0x00, 0x45, 0x00, /* S.....E. */
0x00, 0x30, 0x05, 0xc4, 0x40, 0x00, 0x80, 0x06, /* .0..@... */
0x71, 0xb0, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, /* q....... */
0x01, 0x02, 0x00, 0x15, 0x04, 0x03, 0x21, 0x5d, /* ......!] */
0x3a, 0x44, 0x00, 0x3b, 0xcf, 0x45, 0x70, 0x12, /* :D.;.Ep. */
0x44, 0x70, 0x8c, 0x11, 0x00, 0x00, 0x02, 0x04, /* Dp...... */
0x05, 0xb4, 0x01, 0x01, 0x04, 0x02              /* ...... */
},
/*Trama 21*/
{
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x31, 0x36,
0x38, 0x2e, 0x30, 0x2e, 0x08, 0x06, 0x00, 0x01,
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x31, 0x36,
0x38, 0x2e, 0x30, 0x2e, 0x31, 0x30, 0x00, 0x08,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x39,
0x32, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x47, 0x53, 0x51}};

char* frame(int i)
{
	return trama[i];
}
