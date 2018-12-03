/* Copyright (c) 2012 Thierry Vignaud for Mageia
 * This program is free software; you can redistribute it and/or
 * modify it under the same terms as Perl itself, or under GPL or BSD license.
 */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "cfile.h"
#include "deltarpm.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

char *seq_to_string(unsigned int seql, unsigned char *seq) {
    char *tmp = calloc(seql * 2 + 1, sizeof(char));
    int i;
    for (i = 0; i < seql; i++) {
      char buff[3];
      snprintf(buff, 3, "%02x", seq[i]);
      strcat(tmp, buff);
    }
    return tmp;
}

HV* ReadObjectFromFile(FILE *file) {
  HV * rh;

  char *src_nevr, *target_nevr, *seq;
  int nb;
  unsigned int seql;
  char buf[BUFSIZ];
  fgets(buf, BUFSIZ, file);
  nb = sscanf(buf, "srcnevr=%as targetnevr=%as seql=%d, seq=%as\n", &src_nevr, &target_nevr, &seql, &seq);
  if (nb != 4)
      croak("unable to get deltarpm info");

  rh = newHV();
  hv_store(rh, "src_nevr", 8, newSVpv(src_nevr, 0), 0);
  hv_store(rh, "target_nevr", 11, newSVpv(target_nevr, 0), 0);
  /* Sequence */
  if (seq)
    hv_store(rh, "seq", 3, newSVpv(seq, 0), 0);
  free(seq);
  free(src_nevr);
  free(target_nevr);
  return rh;
}


MODULE = deltarpm            PACKAGE = deltarpm       PREFIX = delta_

SV*
delta_read(filename)
  char *filename;
  PREINIT:
  struct deltarpm d;
  int pid;
  int ipcpipe[2];
  
  CODE:
  /* The delta rpm code does not expect to be used in its way. Its error handling
   * consists of 'printf' and 'exit'. So, dirty hacks abound.
   * Also it's leaky.
   */
  if (pipe(ipcpipe) == -1)
      croak("unable to create pipe");

  if ((pid = fork())) {
    FILE *readend = fdopen(ipcpipe[0], "r");
    int rc, status;

    rc = waitpid(pid, &status, 0);
    if (rc == -1 || (WIFEXITED(status) && WEXITSTATUS(status) != 0))
      croak("unable to read deltarpm file %s (status=%d)", filename, status);

    
    RETVAL = sv_2mortal((SV*)SvREFCNT_inc(newRV_noinc((SV *)ReadObjectFromFile(readend))));
    fclose(readend);
  } else {
    char *tmp;
    FILE *writend = fdopen(ipcpipe[1], "w");

    readdeltarpm(filename, &d, NULL);
    if (d.seql)
      tmp = seq_to_string(d.seql, d.seq);
    fprintf(writend, "srcnevr=%s targetnevr=%s seql=%d, seq=%s\n", d.nevr, d.targetnevr, d.seql,
	    d.seql ? tmp : "");
    fclose(writend);
    free(tmp);
    _exit(0);
  }
  close(ipcpipe[1]);
OUTPUT:
RETVAL

