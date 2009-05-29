#include "mpi.h"
#include "swill/swill.h"

int rank;
void foo() {
   printf("foo %d\n", rank);
}

int main(int argc, char* argv[])
{
   MPI_Init(&argc, &argv);
   MPI_Comm_rank(MPI_COMM_WORLD,&rank);

   swill_init(8080);
   swill_handle("stdout:foo.txt", foo, NULL);

   while(1){
      sleep(1);
      swill_poll();
   }
   return 0;
}
