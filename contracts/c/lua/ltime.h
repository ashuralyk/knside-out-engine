
#ifndef ltime_h
#define ltime_h

#define time(x) ltime(x)
#define clock() lclock()

long int ltime(long int *ptr);
long int lclock(void);

#endif
