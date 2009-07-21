
struct rpmpay {
  char *name;
  unsigned int x;
  unsigned int lx;
  off64_t o;
  unsigned int l;
};

int rpmoffs(FILE *fp, char *isoname, struct rpmpay **retp);

