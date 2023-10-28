#define SIZE 1024
//int __attribute__((aligned(4096))) ;
int sum = 0;
int _start() {
  int A[SIZE] = { 0 };
  for (int i = 0; i < SIZE; i++) A[i] = 2;
  for (int i = 0; i < SIZE; i++)
    sum += A[i];
  return sum;
}
