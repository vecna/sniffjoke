/***********************************************
 * Sine-Gordon
 *
 * Solves the Sine-Gordon Equation.
 *
 * Dave Beazley
 * May 25, 1993
 *
 * Modified for SWILL - April 21, 2001
 ***********************************************/

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "swill/swill.h"

#include "gifplot.h"

#define  PI 3.14159265359

/* Some global variables */

double *u = 0;    /* Positions */
double *v = 0;    /* Velocities */
double *a = 0;
double *b = 0;      
double *c = 0;
double *d = 0;
double *temp = 0;  /* Temporary */
int     Npoints;
double  Dt;
double  Time;
double  Xmin;
double  Xmax;
int     Totalsteps = 0;

ColorMap    *cm = 0;   /* Colormap for plotting */

/* -----------------------------------------------------------------------------
 * Create a new simulation
 * ----------------------------------------------------------------------------- */

void init_sg(int npts) {
   int i;
   Npoints = npts;
   u = (double *) malloc((npts+1)*sizeof(double));
   v = (double *) malloc((npts+1)*sizeof(double));
   a  = (double *) malloc((npts+1)*sizeof(double));
   b  = (double *) malloc((npts+1)*sizeof(double));
   c  = (double *) malloc((npts+1)*sizeof(double));
   d  = (double *) malloc((npts+1)*sizeof(double));

   for (i = 0; i <= npts; i++) {
      u[i] = v[i] = a[i] = b[i] = c[i] = d[i] = 0.0;
   }
   temp = (double *) malloc((npts+1)*sizeof(double));
}

/************************************************
 Solves the Sine-Gordon Equation
        Utt = Uxx - Sin U
	Ux(0) = 0
	Ux(L) = 0
	U(x,0) = f(x)
        Ut(x,0)= g(x) 

************************************************/

/*/ Solve Sine-Gordon Equation for n steps */

void solve_sg(int nsteps) {
   double  h,k,r,t,p,x,y,h2,k2;
   void   tridiagonal(double *, double *, double *, double *, double *, int);
   int    i,j;

   h = (Xmax - Xmin)/(double) Npoints;
   k = Dt;

   /* Set up initial conditions */
     
   h2 = h*h;
   k2 = k*k;

   /* Calculate tridiagonal Matrix coefficients on first iteration */

   if (!Totalsteps) {
      a[0] = 0;
      c[0] = -2*k2;
      c[Npoints] = 0;
      a[Npoints] = -2*k2;
      for (i = 1; i < Npoints; i++) {
	 a[i] = -k2;
	 c[i] = -k2;
      }
      for (i = 0; i <= Npoints; i++) {
	 b[i] = 2*(2*h2 + k2);
      }
    
      /* Calculate RHS */
    
      d[0] = 2*k2*u[1] + (4*h2-2*k2)*u[0] + 4*h2*k*v[0] - 2*h2*k2*sin(u[0]);
      d[Npoints] = 2*k2*u[Npoints-1] + (4*h2-2*k2)*u[Npoints] + 4*h2*k*v[Npoints] - 2*h2*k2*sin(u[Npoints]);
      for (i = 1; i < Npoints; i++) {
	 d[i] = k2*(u[i+1]+u[i-1])+(4*h2-2*k2)*u[i] +4*h2*k*v[i] - 2*h2*k2*sin(u[i]);
      }
    
      tridiagonal(a,b,c,d,v, Npoints+1);

      /* Adjust crank-nicholson coefficients */

      for (i = 0; i <= Npoints; i++) {
	 b[i] = 2*(h2 + k2);
      }
   }     

   for (i = 1; i <= nsteps; i++) {
      /* Set up RHS */
      d[0] = 2*k2*v[1] + (4*h2-2*k2)*v[0] -2*h2*u[0] - 2*h2*k2*sin(v[0]);
      for (j = 1; j < Npoints; j++) {
	 d[j] = k2*(v[j+1]+v[j-1])+(4*h2-2*k2)*v[j] - 2*h2*u[j] - 2*h2*k2*sin(v[j]);
      }
      d[Npoints] = 2*k2*v[Npoints-1] + (4*h2-2*k2)*v[Npoints] - 2*h2*u[Npoints] - 2*h2*k2*sin(v[Npoints]);

      tridiagonal(a,b,c,d,temp, Npoints+1);	  

      /* Copy solutions */

      for (j = 0; j <= Npoints; j++) {
	 u[j] = v[j];
	 v[j] = temp[j];
      }

      Time += Dt;
      Totalsteps++;
   }
}

/* Equation for a kink with velocity V and center x0 */
double eval_kink(double x, double v, double x0, double k) {
   double y;
   y = 4*atan(exp((x-x0)/sqrt(1-v*v))) + 2*PI*k;
   return(y);
}
double eval_dkink(double x, double v, double x0) {
   double y;
   y = -4*v*exp((x-x0)/sqrt(1-v*v))/(sqrt(1-v*v)*(1+exp((x-x0)/sqrt(1-v*v))*exp((x-x0)/sqrt(1-v*v))));
   return(y);
}

double eval_antikink(double x, double v, double x0, double k) {
   double y;
   y = 4*atan(exp(-(x-x0)/sqrt(1-v*v))) + 2*PI*k;
   return(y);
}

double eval_dantikink(double x, double v, double x0) {
   double y;
   y = 4*v*exp(-(x-x0)/sqrt(1-v*v))/(sqrt(1-v*v)*(1+exp(-(x-x0)/sqrt(1-v*v))*exp(-(x-x0)/sqrt(1-v*v))));
   return(y);
}

/* Kink equations */

/* Add a kink to the initial state */
void sg_kink(double vel, double x0, double k) {

   double h,x;
   int i;

   h = (Xmax - Xmin)/ (double) Npoints;
   for (i = 0; i <= Npoints; i++) {
      x = Xmin+i*h;
      u[i] += eval_kink(x,vel,x0,k);
      v[i] += eval_dkink(x,vel,x0);
   }
  
}

void sg_antikink(double vel, double x0, double k) {

   double h,x;
   int i;

   h = (Xmax - Xmin)/ (double) Npoints;
   for (i = 0; i <= Npoints; i++) {
      x = Xmin+i*h;
      u[i] += eval_antikink(x,vel,x0,k);
      v[i] += eval_dantikink(x,vel,x0);
   }
}

/* Solve tridiagonal matrix */
#define MAXSIZE 128000

void tridiagonal(double *a, double *b, double *c, double *d, double *u, int N) {

   int i,j,k;
   static double P[MAXSIZE];
   static double R[MAXSIZE];

   P[0] = b[0];
   R[0] = d[0]/b[0];

   for (i = 1; i < N; i++) {
      P[i] = b[i] - (a[i]*c[i-1])/P[i-1];
      R[i] = (d[i] - a[i]*R[i-1])/P[i];
   }

   u[N-1] = R[N-1];
   for (i = N-2; i >= 0; i--)
      u[i] = R[i] - (c[i]*u[i+1])/P[i];


}

/* Print the points out */
void print_points() {
   int i;
   double h;
   h = (Xmax - Xmin)/Npoints;
   printf("Points: Time = %g\n", Time);
   for (i = 0; i < Npoints; i++) {
      printf("%20g %20g\n", i*h, u[i]);
   }
}

void abort_simulation() {
   /*  exit(1);*/
   printf("Really, this would normally abort.\n");
}

void print_info() {
   printf("Sine Gordon solver\n\n");
   printf("Points       : %d\n", Npoints);
   printf("Dt           : %g\n", Dt);
   printf("Xmin         : %g\n", Xmin);
   printf("Xmax         : %g\n", Xmax);
   printf("Current time : %g\n", Time);
}

/* This function makes a plot and writes it to the file f */
void make_plot(FILE *f, Plot2D *p) {
  
   double x1,x2,y1,y2;
   double h;
   char   buffer[512000];
   int    len;
   int     i;

   Plot2D_clear(p,BLACK);
   Plot2D_xaxis(p,0,0,(Xmax-Xmin)/10,4,WHITE);
   Plot2D_yaxis(p,0,0,5.0,4,WHITE);

   h = (Xmax-Xmin)/Npoints;
   x1 = Xmin;
   y1 = u[0];
   for (i = 1; i < Npoints; i++) {
      x2 = i*h;
      y2 = u[i];
      Plot2D_line(p,x1,y1,x2,y2,YELLOW);
      x1 = x2;
      y1 = y2;
   }
   sprintf(buffer,"SineGordon : Time = %0.5f", Time);

   FrameBuffer_drawstring(p->frame,10,580, WHITE, BLACK, buffer, HORIZONTAL);
   len = FrameBuffer_makeGIF(p->frame, cm, buffer, 512000);
   fwrite(buffer,len,1,f);
}

int main(int argc, char **argv) {
   int maxsteps;
   double dt;
   int npoints;
   int   outf;
   int   i;
   FrameBuffer *f;
   FILE   *log;

   Plot2D      *plot = 0;

   printf("Sine-Gordon Solver\n");
   printf("Enter npoints   : ");
   scanf("%d", &npoints);
   printf("Enter timestep  : ");
   scanf("%lf", &dt);
   printf("Enter nsteps    : ");
   scanf("%d", &maxsteps);
   printf("Output freq     : ");
   scanf("%d", &outf);
  
  
   init_sg(npoints);
   Dt = dt;


   Xmax = 100.0;
   Xmin = 0.0;

   /* Add some kinks and antikinks */
   sg_kink(0.9,10,0);
   sg_antikink(0.9,20,-1);
   sg_kink(-0.9,80,0);
   sg_antikink(-0.9,90,-1);

   sg_antikink(0.50,45,-1);  
   sg_kink(0.50,55,0);


   i = 0;
   /*  print_points(); */

   print_info();

   /* Set up a nice plotting object */
  
   f = new_FrameBuffer(600,600);
   cm = new_ColorMap(0);
   plot = new_Plot2D(f,0,-15,100,15);

  
   /* Initialize the SWILL server */
   swill_init(8080);
  
   log = fopen("logfile","w");

   swill_title("Sine-Gordon Solver");
   swill_log(log);

   swill_handle("stdout:points.txt",print_points,0);
   swill_handle("stdout:info.txt",print_info,0);
   swill_handle("stdout:abort",abort_simulation,0);
   swill_handle("plot.gif",make_plot,plot);
   swill_file("index.html",0);
   swill_file("logfile",0);
   swill_file("sg.c",0);
   while (i < maxsteps) {
      solve_sg(outf);
      /*    print_points(); */
      i += outf;
      printf("%d\n", Totalsteps);
      swill_poll();
   }
}



