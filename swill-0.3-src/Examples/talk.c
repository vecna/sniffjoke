#include "swill/swill.h"
#include "gd.h"
#include <stdlib.h>

/* hello_txt */
void hello_txt(FILE *f){
   int i;
   fprintf(f, "Hello world!\n");
   for (i = 0; i < 10; i++) {
      fprintf(f,"%d\n", i);
   }
}

int count = 0;
void hello_count(FILE *f) {
   fprintf(f,"Hello world!\n");
   fprintf(f,"I've counted to %d\n", count);
}

/* hello_html */
void hello_html(FILE *f){
   int i;
   fprintf(f, "<html><body><h3>Hello World!</h3>\n");
   fprintf(f,"<ul>\n");
   for (i = 0; i < 10; i++) {
      fprintf(f,"<li>%d\n", i);
   }
   fprintf(f,"</ul></body></html>\n");
}

void fibonacci(FILE *f) {
   int first,second;
   int n;
   if (!swill_getargs("i(n)",&n)) {
      fprintf(f,"Missing form variable!\n");
   } else {
      fprintf(f,"Fibonacci numbers\n");
      first = 0;
      second= 1;
      while (n > 0) {
	 int fib = first + second;
	 fprintf(f,"%d\n", first);
	 first = second;
	 second = fib;
	 n--;
      }
   }
}



/* mandelbrot_png */

/* Structure containing plot data */
typedef struct {
   double  Xmin;
   double  Xmax;
   double  Ymin;
   double  Ymax;
   int     Tolerance;
   gdImagePtr  im;
} MandelData;

void right_arrow(FILE *f) {
   gdImagePtr im;
   int  black;
   int  white;
   int  col;
   im = gdImageCreate(30,21);
   black = gdImageColorAllocate(im,0,0,0);
   white = gdImageColorAllocate(im,255,255,255);
   col   = gdImageColorAllocate(im,rand() % 255, rand() % 255, rand() % 255);

   gdImageFilledRectangle(im,0,0,34,20,white);
   gdImageLine(im,5,6,5,14,black);
   gdImageLine(im,5,6,15,6,black);
   gdImageLine(im,5,14,15,14,black);
   gdImageLine(im,15,6,15,0,black);
   gdImageLine(im,15,0,25,10,black);
   gdImageLine(im,15,14,15,20,black);
   gdImageLine(im,15,20,25,10,black);
   gdImageFillToBorder(im,6,7,black,col);
   gdImagePng(im,f);  
   gdImageDestroy(im);
}

void left_arrow(FILE *f) {
   gdImagePtr im;
   int  black;
   int  white;
   int  col;
   im = gdImageCreate(30,21);
   black = gdImageColorAllocate(im,0,0,0);
   white = gdImageColorAllocate(im,255,255,255);
   col   = gdImageColorAllocate(im,rand() % 255, rand() % 255, rand() % 255);

   gdImageFilledRectangle(im,0,0,34,20,white);
   gdImageLine(im,25,6,25,14,black);
   gdImageLine(im,25,6,15,6,black);
   gdImageLine(im,25,14,15,14,black);
   gdImageLine(im,15,6,15,0,black);
   gdImageLine(im,15,0,5,10,black);
   gdImageLine(im,15,14,15,20,black);
   gdImageLine(im,15,20,5,10,black);
   gdImageFillToBorder(im,24,7,black,col);
   gdImagePng(im,f);  
   gdImageDestroy(im);
}

/* Handler function that draws an image */

void mandel_png(FILE *f, MandelData *m) {
   double scalingx;
   double scalingy;
   double zr,zi,ztr,zti,cr,ci;
   double cscale;
   int    i,j,n;

   scalingx = (m->Xmax-m->Xmin)/m->im->sx;
   scalingy = (m->Ymax-m->Ymin)/m->im->sy;
   cscale = 256.0/m->Tolerance;
   for (i = 0; i < m->im->sx; i++) {
      for (j = 0; j < m->im->sy; j++) {
	 zr = scalingx*i + m->Xmin;
	 zi = scalingy*j + m->Ymin;
	 cr = zr;
	 ci = zi;
	 n = 0;
	 while (n < m->Tolerance) {
	    ztr = zr*zr-zi*zi + cr;
	    zti = 2*zr*zi + ci;
	    zr = ztr;
	    zi = zti;
	    if (ztr*ztr + zti*zti > 20) break;
	    n = n + 1;
	 }
	 if (n >= m->Tolerance) gdImageSetPixel(m->im,i,j,0);
	 else gdImageSetPixel(m->im,i,j,(int) (n*cscale));
      }
   }
   gdImagePng(m->im,f);
}

void mandel_html(FILE *f, MandelData *m){
   double shift = 100;

   fprintf(f,"<HTML><BODY BGCOLOR=\"#ffffff\">\n");
   if (!swill_getargs("d(shift)", &shift)){
      fprintf(f,"<b>Missing form variable!</b>\n");
   }
   shift = shift/100.0;
  
   m->Xmin = m->Xmin/shift;
   m->Xmax = m->Xmax/shift;
   m->Ymin = m->Ymin/shift;
   m->Ymax = m->Ymax/shift;
  
   fprintf(f,"<p><center><img src=\"mandel.png\"></center>\n");
  
   fprintf(f,"<p><form action=\"mandel.html\" method=GET>\n");
   fprintf(f,"Zoom : <input type=text name=shift width=10 value=\"%g\"></input><br>\n", shift);
   fprintf(f,"<input type=submit value=\"Submit\"></input>\n");
   fprintf(f,"</form>\n");
   fprintf(f,"</body></html>\n");
}

/* system cmd */

void system_txt(){
   system("ps -la");
}


/* -----------------------------------------------------------------------------
   Game of life
   ----------------------------------------------------------------------------- */

#define XPOINTS  200
#define YPOINTS  200

int lifegrid[XPOINTS][YPOINTS];
int nextgrid[XPOINTS][YPOINTS];
int nrounds = 0;

void life_init() {
   int i,j;
   for (i = 0; i < XPOINTS; i++) {
      for (j = 0; j < YPOINTS; j++) {
	 if ((rand() % 2)) {
	    lifegrid[i][j] = 1;
	 } else {
	    lifegrid[i][j] = 0;
	 }
      }
   }
   nrounds = 0;
}

void life_round() {
   int i,j;
   int n,m;
   int count;
   int nlive = 0;
   for (i = 0; i < XPOINTS; i++) {
      for (j = 0; j < YPOINTS; j++) {
	 count = -1;
	 for (n = i - 1; n <= i+1; n++) {
	    if ((n < 0) || (n >= XPOINTS)) continue;
	    for (m = j-1; m <= j+1; m++) {
	       if ((m < 0) || (m >= YPOINTS)) continue;
	       if (lifegrid[n][m]) count++;
	    }
	 }

	 if (lifegrid[i][j]) {
	    if (!((count == 2) || (count == 3))) nextgrid[i][j] = 0;  /* Dead */
	    else {
	       nextgrid[i][j] = 1;  /* Stay alive */
	       nlive++;
	    }
	 } else {
	    if ((count == 3)) {
	       nextgrid[i][j] = 1;  /* Birth */
	       nlive++;
	    } else {
	       nextgrid[i][j] = 0;  /* Stay dead */
	    }
	 }
      }
   }
   nrounds++;
   memmove(lifegrid,nextgrid, sizeof(int)*XPOINTS*YPOINTS);
   if ((!nlive) || (nrounds > 100)) life_init();
   printf("%d\n", nrounds);
}

/* Draw game board */
void life_png(FILE *f) {
   gdImagePtr im;
   int  black;
   int  white;
   int  col;
   int  i,j;
   im = gdImageCreate(XPOINTS,YPOINTS);
   black = gdImageColorAllocate(im,0,0,0);
   white = gdImageColorAllocate(im,255,255,255);
   col   = gdImageColorAllocate(im,0,255,0);
   gdImageFilledRectangle(im,0,0,XPOINTS-1,YPOINTS-1,black);

   life_round();
   for (i = 0; i < XPOINTS; i++) {
      for (j = 0; j < YPOINTS; j++) {
	 if (lifegrid[i][j]) {
	    gdImageSetPixel(im,i,j,col);
	 }
      }
   }
	
   gdImagePng(im,f);  
   gdImageDestroy(im);
}

int main() {
   int i;
   MandelData *m;
   MandelData *m1;
   MandelData *m2;

   /* mandel stuff */
   m = (MandelData *) malloc(sizeof(MandelData));
   m->Xmin = -2.0;
   m->Xmax = 2.0;
   m->Ymin = -2.0;
   m->Ymax = 2.0;
   m->Tolerance = 50;
   m->im = gdImageCreate(400,400);

   m1 = (MandelData *) malloc(sizeof(MandelData));
   m1->Xmin = -1.0;
   m1->Xmax = 1.0;
   m1->Ymin = -1.0;
   m1->Ymax = 1.0;
   m1->Tolerance = 50;
   m1->im = gdImageCreate(250,250);

   m2 = (MandelData *) malloc(sizeof(MandelData));
   m2->Xmin = -1.0;
   m2->Xmax = 0.0;
   m2->Ymin = -1.0;
   m2->Ymax = 0.0;
   m2->Tolerance = 50;
   m2->im = gdImageCreate(250,250);

   /* Allocate colormap */
   for (i = 0; i < 256; i++) {
      gdImageColorAllocate(m->im,i/2,i,i);
      gdImageColorAllocate(m1->im,i,i/2,i);
      gdImageColorAllocate(m2->im,i,i,i/2);
   }
  
   /* start swill */
   if (swill_init(8080)) {
      printf("SWILL listening on port 8080\n");
   } else {
      printf("Couldn't initialize the server.\n");
      exit(1);
   }

   swill_title("SWILL Examples");

   swill_handle("hello.txt", hello_txt, 0);
   swill_handle("hellocount.txt", hello_count,0);
   swill_handle("hello.html", hello_html, 0);
   swill_handle("mandel.png", mandel_png, m);
   swill_handle("mandel1.png", mandel_png,m1);
   swill_handle("mandel2.png", mandel_png,m2);
   swill_handle("right.png", right_arrow, 0);
   swill_handle("left.png", left_arrow, 0);
   swill_handle("fib.txt", fibonacci,0);
   swill_handle("mandel.html", mandel_html, m);
   swill_handle("stdout:ps.txt", system_txt, 0);
   swill_handle("life.png", life_png,0);

   swill_directory("../Talk/Slides");

   swill_file("passwd", "/etc/passwd");

   swill_log(stdout);

   life_init();
   while(1) {
      count++;
      swill_poll();
   }

}

