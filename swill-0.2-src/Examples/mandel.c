/* SWILL Mandelbrot example */

#include "swill/swill.h"
#include "gd.h"

/* Structure containing plot data */
typedef struct {
   double  Xmin;
   double  Xmax;
   double  Ymin;
   double  Ymax;
   int     Tolerance;
   gdImagePtr  im;
} MandelData;

/* Handler function that draws an image */

void mandel(FILE *f, MandelData *m) {
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

/* Handler that produces HTML form for changing values */

void mandelpage(FILE *f, MandelData *m) {
   double xmin, xmax, ymin, ymax;
   double xshift,yshift;
   int tol;
   fprintf(f,"<HTML><BODY BGCOLOR=\"#ffffff\">\n");
   if (!swill_getargs("d(xmin)d(xmax)d(ymin)d(ymax)i(tol)", &xmin,&xmax,&ymin,&ymax,&tol)) {
      fprintf(f,"<b>Missing form variable!</b>\n");
   } else {
      m->Xmin = xmin;
      m->Xmax = xmax;
      m->Ymin = ymin;
      m->Ymax = ymax;
      m->Tolerance = tol;
   }

   /* Link to image picture */
   fprintf(f,"<p><center><img src=\"mandel.png\"></center>\n");

   xshift = (m->Xmax - m->Xmin)/4;
   yshift = (m->Ymax - m->Ymin)/4;

   fprintf(f,"<center><p>\n");
   fprintf(f,"<a href=\"");
   swill_printurl(f,"mandelpage.html","d(xmin)d(xmax)d(ymin)d(ymax)i(tol)",
		  m->Xmin-xshift,m->Xmax-xshift,m->Ymin,m->Ymax,m->Tolerance);
   fprintf(f,"\">[ Left ]</a>");

   fprintf(f,"<a href=\"");
   swill_printurl(f,"mandelpage.html","d(xmin)d(xmax)d(ymin)d(ymax)i(tol)",
		  m->Xmin+xshift,m->Xmax+xshift,m->Ymin,m->Ymax,m->Tolerance);
   fprintf(f,"\">[ Right ]</a>");

   fprintf(f,"<a href=\"");
   swill_printurl(f,"mandelpage.html","d(xmin)d(xmax)d(ymin)d(ymax)i(tol)",
		  m->Xmin,m->Xmax,m->Ymin-yshift,m->Ymax-yshift,m->Tolerance);
   fprintf(f,"\">[ Up ]</a>");

   fprintf(f,"<a href=\"");
   swill_printurl(f,"mandelpage.html","d(xmin)d(xmax)d(ymin)d(ymax)i(tol)",
		  m->Xmin,m->Xmax,m->Ymin+yshift,m->Ymax+yshift,m->Tolerance);
   fprintf(f,"\">[ Down ]</a>");

   fprintf(f,"<a href=\"");
   swill_printurl(f,"mandelpage.html","d(xmin)d(xmax)d(ymin)d(ymax)i(tol)",
		  m->Xmin+xshift,m->Xmax-xshift,m->Ymin+yshift,m->Ymax-yshift,m->Tolerance);
   fprintf(f,"\">[ Zoom in ]</a>");

   fprintf(f,"<a href=\"");
   swill_printurl(f,"mandelpage.html","d(xmin)d(xmax)d(ymin)d(ymax)i(tol)",
		  m->Xmin-xshift,m->Xmax+xshift,m->Ymin-yshift,m->Ymax+yshift,m->Tolerance);
   fprintf(f,"\">[ Zoom out ]</a>");
  
   fprintf(f,"</center>\n");

   /* Form to change values manually */
   fprintf(f,"<p><form action=\"mandelpage.html\" method=GET>\n");
   fprintf(f,"Xmin : <input type=text name=xmin width=10 value=\"%g\"></input><br>\n", m->Xmin);
   fprintf(f,"Xmax : <input type=text name=xmax width=10 value=\"%g\"></input><br>\n", m->Xmax);
   fprintf(f,"Ymin : <input type=text name=ymin width=10 value=\"%g\"></input><br>\n", m->Ymin);
   fprintf(f,"Ymax : <input type=text name=ymax width=10 value=\"%g\"></input><br>\n", m->Ymax);
   fprintf(f,"Tolerance : <input type=text name=tol width=10 value=\"%d\"></input><br>\n", m->Tolerance);
   fprintf(f,"<input type=submit value=\"Submit\"></input>\n");
   fprintf(f,"</form>\n");
   fprintf(f,"</body></html>\n");
}

int main(int argc, char **argv) {
   int i;
   MandelData *m;

   printf("Mandelbrot set viewer\n");
  
   m = (MandelData *) malloc(sizeof(MandelData));
   m->Xmin = -2.0;
   m->Xmax = 2.0;
   m->Ymin = -2.0;
   m->Ymax = 2.0;
   m->Tolerance = 50;
   m->im = gdImageCreate(400,400);

   /* Allocate colormap */
   for (i = 0; i < 256; i++) {
      gdImageColorAllocate(m->im,i/2,i,i);
   }
  
   if (swill_init(8080)) {
      printf("Server listening on port 8080\n");
   } else {
      printf("Couldn't start server!\n");
      exit(1);
   }
   swill_handle("mandel.png", mandel, m);
   swill_handle("mandelpage.html", mandelpage,m);
   swill_handle("index.html",mandelpage,m);
   while (1) {
      swill_serve();
   }

}




