/* Copyright 2009 Red Hat, Inc.
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include "Python.h"
#include "marshal.h"
#include "cfile.h"
#include "deltarpm.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

PyObject *createDict(struct deltarpm d)
{
  PyObject *dict;
  PyObject *o;
  
  dict = PyDict_New();
  
  /* Old NEVR */
  if (d.nevr) {
    o = PyString_FromString(d.nevr);
    PyDict_SetItemString(dict, "old_nevr", o);
    Py_DECREF(o);
  } else {
    PyDict_SetItemString(dict, "old_nevr", Py_None);
  }
  
  /* New NEVR */
  if (d.targetnevr) {
    o = PyString_FromString(d.targetnevr);
    PyDict_SetItemString(dict, "nevr", o);
    Py_DECREF(o);
  } else {
    PyDict_SetItemString(dict, "nevr", Py_None);
  }
  
  /* Sequence */
  if (d.seq) {
    char *tmp = calloc(d.seql * 2 + 1, sizeof(char));
    int i;
    for (i = 0; i < d.seql; i++) {
      char buf[3];
      
      snprintf(buf, 3, "%02x", d.seq[i]);
      strcat(tmp, buf);
    }
    o = PyString_FromString(tmp);
    free(tmp);
    PyDict_SetItemString(dict, "seq", o);
    Py_DECREF(o);
  } else {
    PyDict_SetItemString(dict, "seq", Py_None);
  }
  return dict;
}

static PyObject *doRead(PyObject *s, PyObject *args)
{
  char *filename;
  struct deltarpm d;
  PyObject *ret;
  int pid;
  int ipcpipe[2];
  
  if (!PyArg_ParseTuple(args, "s", &filename)) {
    PyErr_SetFromErrno(PyExc_SystemError);
    return NULL;
  }

  /* The delta rpm code does not expect to be used in its way. Its error handling
   * conststs of 'printf' and 'exit'. So, dirty hacks abound. */
  if (pipe(ipcpipe) == -1) {
    PyErr_SetFromErrno(PyExc_SystemError);
    return NULL;
  }

  if ((pid = fork())) {
    FILE *readend = fdopen(ipcpipe[0], "r");
    int rc, status;

    rc = waitpid(pid, &status, 0);
    if (rc == -1 || (WIFEXITED(status) && WEXITSTATUS(status) != 0)) {
      PyErr_SetFromErrno(PyExc_SystemError);
      return NULL;
    }
    ret = PyMarshal_ReadObjectFromFile(readend);
    fclose(readend);
  } else {
    FILE *writend = fdopen(ipcpipe[1], "w");

    readdeltarpm(filename, &d, NULL);
    PyMarshal_WriteObjectToFile(createDict(d), writend, Py_MARSHAL_VERSION);
    fclose(writend);
    _exit(0);
  }
  close(ipcpipe[1]);
  return ret;
}

static PyMethodDef deltarpmMethods[] = {
  { "read", (PyCFunction) doRead, METH_VARARGS, NULL },
  { NULL }
};

void init_deltarpm(void)
{
  PyObject *m;
  
  m = Py_InitModule("_deltarpm", deltarpmMethods);
}
