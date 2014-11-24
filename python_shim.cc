extern "C" {
#include <Python.h>
}

#include <memory>

#include "flowparser.h"

namespace flowparser {
namespace python_shim {

struct PythonFlowParser {
  PyObject_HEAD

  std::unique_ptr<FlowParser> flow_parser;
  PyObject* error_callback;
};

static void FparserDealloc(PythonFlowParser* fparser) {
  Py_XDECREF(fparser->error_callback);
  fparser->flow_parser.release();
}

static PyObject* FparserNew(PyTypeObject *type, PyObject *args,
                            PyObject *kwds) {
  PythonFlowParser* self = nullptr;
  PyObject *error_callback = nullptr;
  char* source = nullptr;

  static char* argnames[] = { "source", "error_callback", nullptr };

  std::cout << "Hello0\n";
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O", argnames, &source,
                                   &error_callback)) {
    return nullptr;
  }

  std::cout << "Hello\n";
  if (error_callback && !PyCallable_Check(error_callback)) {
    PyErr_SetString(PyExc_TypeError, "Error callback must be callable");
    return nullptr;
  }
  std::cout << "Hello 2\n";

  self = (PythonFlowParser*) type->tp_alloc(type, 0);
  std::cout << "FP " << self << "\n";

  if (error_callback) {
    Py_INCREF(error_callback);
    self->error_callback = error_callback;
  }

  return (PyObject*) self;
}

static PyMethodDef fparser_methods[] = { { NULL, NULL, 0, NULL } };

PyTypeObject fparser_type = { PyObject_HEAD_INIT(NULL) 0, /*ob_size*/
"fparser.FParser", /*tp_name*/
sizeof(PythonFlowParser), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) FparserDealloc, /*tp_dealloc*/
0, /*tp_print*/
0, /*tp_getattr*/
0, /*tp_setattr*/
0, /*tp_compare*/
0, /*tp_repr*/
0, /*tp_as_number*/
0, /*tp_as_sequence*/
0, /*tp_as_mapping*/
0, /*tp_hash */
0, /*tp_call*/
0, /*tp_str*/
0, /*tp_getattro*/
0, /*tp_setattro*/
0, /*tp_as_buffer*/
Py_TPFLAGS_DEFAULT,
/* tp_flags: Py_TPFLAGS_HAVE_ITER tells python to
 use tp_iter and tp_iternext fields. */
"Internal fparser object.", /* tp_doc */
0, /* tp_traverse */
0, /* tp_clear */
0, /* tp_richcompare */
0, /* tp_weaklistoffset */
0, /* tp_iter: __iter__() method */
0, /* tp_iternext: next() method */
fparser_methods, /* tp_methods */
0, /* tp_members */
0, /* tp_getset */
0, /* tp_base */
0, /* tp_dict */
0, /* tp_descr_get */
0, /* tp_descr_set */
0, /* tp_dictoffset */
0, /* tp_init */
0, /* tp_alloc */
FparserNew, /* tp_new */
};

static PyMethodDef fparser_module_methods[] = { { NULL, NULL, 0, NULL } };

}  // namespace python_shim
}  // namespace flowparser

extern "C" {

PyMODINIT_FUNC initfparser(void) {
  PyObject *m;

  m = Py_InitModule("fparser", flowparser::python_shim::fparser_module_methods);
  if (m == nullptr) {
    return;
  }

  if (PyType_Ready(&flowparser::python_shim::fparser_type) < 0) {
    return;
  }

  Py_INCREF(&flowparser::python_shim::fparser_type);
  PyModule_AddObject(m, "FParser",
                     (PyObject *) &flowparser::python_shim::fparser_type);

  PyEval_InitThreads();
}

}
