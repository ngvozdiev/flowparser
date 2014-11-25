// This file implements a C Python module that makes it easy to use flowparser
// from Python. Because of the verbosity of the Python C/C++ API each python
// datatype resides in its own namespace.

extern "C" {
#include <Python.h>
#include <structseq.h>
#include <structmember.h>
}

#include <memory>

#include "../flowparser.h"

namespace flowparser {
namespace python_shim {

// fparser.FlowKey is a namedtuple-like object that is the Python equivalent to
// flowparser::FlowKey. All fields are in host order and src and dst are string
// representations of the source and destination ip addresses.
namespace flow_key {

static PyTypeObject fparser_flow_key_ntuple_type = { 0, 0, 0, 0, 0, 0 };
static PyStructSequence_Field flow_key_ntuple_fields[] = { { "src",
    "The source IP address of the flow" }, { "sport",
    "The source port of the transport header of the flow" }, { "dest",
    "The destination IP address of the flow" }, { "dport",
    "The dest port of the transport header of the flow" }, { nullptr } };

static PyStructSequence_Desc flow_key_ntuple_desc = { "fparser.FlowKey",
    nullptr, flow_key_ntuple_fields, 4 };

// Converts a flowparser::FlowKey to fparser.FlowKey
static PyObject* FromFlowKey(const FlowKey& key) {
  PyObject* ntuple = PyStructSequence_New(&fparser_flow_key_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0,
                            PyString_FromString(key.SrcToString().c_str()));
  PyStructSequence_SET_ITEM(ntuple, 1,
                            PyInt_FromSize_t((size_t ) key.src_port()));
  PyStructSequence_SET_ITEM(ntuple, 2,
                            PyString_FromString(key.DstToString().c_str()));
  PyStructSequence_SET_ITEM(ntuple, 3,
                            PyInt_FromSize_t((size_t ) key.dst_port()));

  return ntuple;
}

}  // namespace flow_key

// fparser.IPHeader is the Python equivalent of flowparser::IPHeader. It
// contains all fields that are tracked by flowparser for every IP packet.
namespace ip_header {

static PyTypeObject fparser_ip_hdr_ntuple_type = { 0, 0, 0, 0, 0, 0 };
static PyStructSequence_Field ip_hdr_ntuple_fields[] = { { "timestamp",
    "PCAP timestamp" }, { "ttl", "TTL value" }, { "len", "IP length" }, { "id",
    "IP id" }, { nullptr } };

static PyStructSequence_Desc ip_hdr_ntuple_desc = { "fparser.IPHeader", nullptr,
    ip_hdr_ntuple_fields, 4 };

// Constructs a new fparser.IPHeader from a flowparser::IPHeader instance.
static PyObject* FromIPHeader(const IPHeader& ip) {
  PyObject* ntuple = PyStructSequence_New(&fparser_ip_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0,
                            PyLong_FromUnsignedLongLong(ip.timestamp));
  PyStructSequence_SET_ITEM(ntuple, 1, PyInt_FromLong(ip.ttl));
  PyStructSequence_SET_ITEM(ntuple, 2, PyInt_FromLong(ip.length));
  PyStructSequence_SET_ITEM(ntuple, 3, PyInt_FromLong(ip.id));

  return ntuple;
}

}  // namespace ip_header

// fparser.TCPHeader is the Python equivalent of flowparser::TCPHeader, with the
// difference that it contains the ip header as a member.
namespace tcp_header {

static PyTypeObject fparser_tcp_hdr_ntuple_type = { 0, 0, 0, 0, 0, 0 };
static PyStructSequence_Field tcp_hdr_ntuple_fields[] = { { "ip", "IP header" },
    { "seq", "TCP sequence number" }, { "ack", "TCP ack number" }, { "win",
        "TCP window" }, { "flags", "TCP flags" }, { nullptr } };

static PyStructSequence_Desc tcp_hdr_ntuple_desc = { "fparser.TCPHeader",
    nullptr, tcp_hdr_ntuple_fields, 5 };

static PyObject* FromTCPHeader(const IPHeader& ip, const TCPHeader& tcp) {
  PyObject* ntuple = PyStructSequence_New(&fparser_tcp_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0, ip_header::FromIPHeader(ip));
  PyStructSequence_SET_ITEM(ntuple, 1, PyLong_FromUnsignedLongLong(tcp.seq));
  PyStructSequence_SET_ITEM(ntuple, 2, PyLong_FromUnsignedLongLong(tcp.ack));
  PyStructSequence_SET_ITEM(ntuple, 3, PyInt_FromLong(tcp.win));
  PyStructSequence_SET_ITEM(ntuple, 4, PyInt_FromLong(tcp.flags));

  return ntuple;
}

}  // namespace tcp_header

// fparser.TCPFlow is the Python equivalent of flowparser::TCPFlow.
namespace tcp_flow {

// The main struct that holds a flow, its key and an iterator as unique
// pointers.
struct PythonTCPFlow {
  PyObject_HEAD

  uint64_t size_pkts;  // number of packets in the flow
  std::unique_ptr<const TCPFlow> flow;
  std::unique_ptr<const FlowKey> key;
  std::unique_ptr<TCPFlowIterator> it;  // iterator
};

// Frees a PythonTCPFlow
static void PythonTCPFlowDealloc(PythonTCPFlow* fparser_flow) {
  fparser_flow->ob_type->tp_free((PyObject *) fparser_flow);
}

// Returns the flow's id.
static PyObject* PythonTCPFlowGetId(PyObject* self) {
  const PythonTCPFlow* py_flow = (PythonTCPFlow*) self;
  const FlowKey& key = *py_flow->key;

  return flow_key::FromFlowKey(key);
}

// Returns the number of packets in the flow.
static Py_ssize_t PythonTCPFlowGetLen(PyObject* self) {
  const PythonTCPFlow* py_flow = (PythonTCPFlow*) self;
  return (Py_ssize_t) py_flow->size_pkts;
}

// The flow's iterator is just the flow object itself - the it field is
// populated with the most recent iterator.
static PyObject* PythonTCPFlowIter(PyObject* self) {
  Py_INCREF(self);
  return self;
}

// Gets the next object from the iterator, or raises a StopIteration exception
// and resets the iterator.
static PyObject* PythonTCPFlowIternext(PyObject* self) {
  PythonTCPFlow* py_flow = (PythonTCPFlow*) self;

  IPHeader ip_header;
  TCPHeader tcp_header;
  bool has_more = py_flow->it->Next(&ip_header, &tcp_header);
  if (!has_more) {
    py_flow->it = std::make_unique<TCPFlowIterator>(*py_flow->flow);
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
  }

  return tcp_header::FromTCPHeader(ip_header, tcp_header);
}

// The methods of a PythonTCPFlow object.
static PyMethodDef python_tcp_flow_methods[] = { { "get_id",
    (PyCFunction) PythonTCPFlowGetId, METH_NOARGS,
    "Returns (source ip, source port, dest ip, dest port)" }, { nullptr } };

// A PythonTCPFlow is also a sequence of its packets - it needs to have a
// length.
static PySequenceMethods python_tcp_flow_sequence_methods = {
    PythonTCPFlowGetLen, /* sq_length */
};

// Boilerplae for the type.
PyTypeObject python_tcp_flow_type = { PyObject_HEAD_INIT(nullptr) 0, /*ob_size*/
"fparser.TCPFlow", /*tp_name*/
sizeof(PythonTCPFlow), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) PythonTCPFlowDealloc, /*tp_dealloc*/
0, /*tp_print*/
0, /*tp_getattr*/
0, /*tp_setattr*/
0, /*tp_compare*/
0, /*tp_repr*/
0, /*tp_as_number*/
&python_tcp_flow_sequence_methods, /*tp_as_sequence*/
0, /*tp_as_mapping*/
0, /*tp_hash */
0, /*tp_call*/
0, /*tp_str*/
0, /*tp_getattro*/
0, /*tp_setattro*/
0, /*tp_as_buffer*/
Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
/* tp_flags: Py_TPFLAGS_HAVE_ITER tells python to
 use tp_iter and tp_iternext fields. */
"Internal fparser TCP flow object.", /* tp_doc */
0, /* tp_traverse */
0, /* tp_clear */
0, /* tp_richcompare */
0, /* tp_weaklistoffset */
PythonTCPFlowIter, /* tp_iter: __iter__() method */
PythonTCPFlowIternext, /* tp_iternext: next() method */
python_tcp_flow_methods /* tp_methods */
};

// Constructs a new PythonTCPFlow from a combination of a FlowKey and a TCPFlow.
// This function will take ownership of the TCPFlow object and store it as a
// const unique pointer, guaranteeing that the flow will not be modified once it
// is handed off to Python.
static PythonTCPFlow* FromTCPFlow(const FlowKey& key,
                                  std::unique_ptr<TCPFlow> flow) {
  struct PythonTCPFlow* py_flow;

  py_flow = PyObject_New(PythonTCPFlow, (PyTypeObject* ) &python_tcp_flow_type);
  if (!py_flow) {
    return nullptr;
  }

  py_flow->size_pkts = flow->GetInfo().size_pkts;
  py_flow->flow = std::move(flow);
  py_flow->key = std::make_unique<FlowKey>(key);

  py_flow->it = std::make_unique<TCPFlowIterator>(*py_flow->flow);
  return py_flow;
}

}  // namespace tcp_flow

// The main FlowParser Python object. It can be used to parse pcap files or
// perform live traces from Python.
namespace flow_parser {

// This struct owns a FlowParser instance and allows the caller to supply
// callbacks into Python for error / warning conditions and completed flows.
struct PythonFlowParser {
  PyObject_HEAD

  std::unique_ptr<FlowParser> flow_parser;

  // One callback for both errors and warnings. The callback receives a tuple of
  // (string, type).
  PyObject* error_callback;

  // A callback that will be called every time a flow times out. It is called
  // with an instance of the flow object.
  PyObject* flow_callback;
};

template<typename T>
static void OffloadFlowToCallback(PythonFlowParser* py_parser,
                                  const FlowKey& key, T* flow) {
  PyGILState_STATE d_gstate;
  PyObject* arglist;
  PyObject* result;

  if (flow == nullptr) {
    return;
  }

  PyObject* python_flow_key = flow_key::FromFlowKey(key);
  if (python_flow_key == nullptr) {
      return;
    }

  d_gstate = PyGILState_Ensure();

  arglist = Py_BuildValue("(OO)", python_flow_key, flow);
  Py_DECREF(flow);
  Py_DECREF(python_flow_key);

  result = PyObject_CallObject(py_parser->flow_callback, arglist);
  Py_DECREF(arglist);

  if (result == nullptr) {
    PyErr_Print();
  }
  Py_XDECREF(result);
  PyGILState_Release(d_gstate);
}

// Offloads a single TCP flow to the flow callback.
static void PythonFlowParserTCPFlowOffload(PythonFlowParser* py_parser,
                                           const FlowKey& key,
                                           std::unique_ptr<TCPFlow> flow) {
  tcp_flow::PythonTCPFlow* py_flow = tcp_flow::FromTCPFlow(key,
                                                           std::move(flow));
  OffloadFlowToCallback<tcp_flow::PythonTCPFlow>(py_parser, key, py_flow);
}

// Frees a PythonFlowParser instance.
static void PythonFlowParserDealloc(PythonFlowParser* fparser) {
  Py_XDECREF(fparser->error_callback);
  fparser->flow_parser.release();
}

// Creates a new PythonFlowParser instance and initializes it.
static PyObject* PythonFlowParserNew(PyTypeObject *type, PyObject *args,
                                     PyObject *kwds) {
  PythonFlowParser* self = nullptr;
  PyObject *error_callback = nullptr;
  PyObject *flow_callback = nullptr;
  char* source = nullptr;
  char* filter = nullptr;
  bool is_file = false;
  int soft_mem_limit_mb = -1;
  int hard_mem_limit_mb = -1;

  static char* argnames[] = { "source", "flow_callback", "is_file", "filter",
      "soft_mem_limit", "hard_mem_limit", "error_callback", nullptr };

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "sO|isiiOO", argnames, &source,
                                   &flow_callback, &is_file, &filter,
                                   &soft_mem_limit_mb, &hard_mem_limit_mb,
                                   &error_callback)) {
    return nullptr;
  }

  if (!PyCallable_Check(flow_callback)) {
    PyErr_SetString(PyExc_TypeError, "Flow callback must be callable");
    return nullptr;
  }

  if (error_callback && !PyCallable_Check(error_callback)) {
    PyErr_SetString(PyExc_TypeError, "Error callback must be callable");
    return nullptr;
  }

  if (soft_mem_limit_mb > 0 && (hard_mem_limit_mb <= soft_mem_limit_mb)) {
    PyErr_SetString(PyExc_TypeError, "Bad memory limits");
    return nullptr;
  }

  self = (PythonFlowParser*) type->tp_alloc(type, 0);

  Py_INCREF(flow_callback);
  self->flow_callback = flow_callback;

  if (error_callback) {
    Py_INCREF(error_callback);
    self->error_callback = error_callback;
  }

  FlowParserConfig cfg;
  if (is_file) {
    cfg.OfflineTrace(std::string(source));
  } else {
    cfg.OnlineTrace(std::string(source));
  }

  cfg.TCPCallback([self] (const FlowKey& key, unique_ptr<TCPFlow> flow) {
    PythonFlowParserTCPFlowOffload(self, key, std::move(flow));
  });

  if (soft_mem_limit_mb > 0) {
    cfg.MemoryLimits(soft_mem_limit_mb * 1000000.0,
                     hard_mem_limit_mb * 1000000.0);
  }

  self->flow_parser = std::make_unique<FlowParser>(cfg);
  return (PyObject*) self;
}

// Performs a trace synchronously.
static PyObject* PythonFlowParserRunTrace(PyObject* self) {
  const PythonFlowParser* py_parser = (PythonFlowParser*) self;

  Status status = py_parser->flow_parser->RunTrace();
  if (!status.ok()) {
    PyErr_SetString(PyExc_IOError, status.ToString().c_str());
    return nullptr;
  }

  Py_INCREF(Py_None);
  return Py_None;
}

// Methods of the PythonFlowParser object.
static PyMethodDef python_flow_parser_methods[] = { { "run_trace",
    (PyCFunction) PythonFlowParserRunTrace, METH_NOARGS,
    "Blocks and traces until source is exhausted" }, { nullptr, nullptr, 0,
    nullptr } };

// Boilerplate for the PythonFlowParser object type.
PyTypeObject python_flow_parser_type = { PyObject_HEAD_INIT(nullptr) 0, /*ob_size*/
"fparser.FlowParser", /*tp_name*/
sizeof(PythonFlowParser), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) PythonFlowParserDealloc, /*tp_dealloc*/
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
python_flow_parser_methods, /* tp_methods */
0, /* tp_members */
0, /* tp_getset */
0, /* tp_base */
0, /* tp_dict */
0, /* tp_descr_get */
0, /* tp_descr_set */
0, /* tp_dictoffset */
0, /* tp_init */
0, /* tp_alloc */
PythonFlowParserNew, /* tp_new */
};

}  // namespace flow_parser

// Methods of the fparser module.
static PyMethodDef fparser_module_methods[] =
    { { nullptr, nullptr, 0, nullptr } };

}  // namespace python_shim
}  // namespace flowparser

extern "C" {

using flowparser::python_shim::fparser_module_methods;

using flowparser::python_shim::flow_parser::python_flow_parser_type;
using flowparser::python_shim::tcp_flow::python_tcp_flow_type;

using flowparser::python_shim::flow_key::fparser_flow_key_ntuple_type;
using flowparser::python_shim::flow_key::flow_key_ntuple_desc;

using flowparser::python_shim::ip_header::fparser_ip_hdr_ntuple_type;
using flowparser::python_shim::ip_header::ip_hdr_ntuple_desc;

using flowparser::python_shim::tcp_header::fparser_tcp_hdr_ntuple_type;
using flowparser::python_shim::tcp_header::tcp_hdr_ntuple_desc;

PyMODINIT_FUNC initfparser(void) {
  PyObject *m;

  m = Py_InitModule("fparser", fparser_module_methods);
  if (m == nullptr) {
    return;
  }

  if (PyType_Ready(&python_flow_parser_type) < 0) {
    return;
  }

  if (PyType_Ready(&python_tcp_flow_type) < 0) {
    return;
  }

  Py_INCREF(&python_flow_parser_type);
  PyModule_AddObject(m, "FParser", (PyObject*) &python_flow_parser_type);

  Py_INCREF(&python_tcp_flow_type);
  PyModule_AddObject(m, "TCPFlow", (PyObject *) &python_tcp_flow_type);

  PyStructSequence_InitType(&fparser_flow_key_ntuple_type,
                            &flow_key_ntuple_desc);
  Py_INCREF(&fparser_flow_key_ntuple_type);
  PyModule_AddObject(m, "FlowKey", (PyObject*) &fparser_flow_key_ntuple_type);

  PyStructSequence_InitType(&fparser_ip_hdr_ntuple_type, &ip_hdr_ntuple_desc);
  Py_INCREF(&fparser_ip_hdr_ntuple_type);
  PyModule_AddObject(m, "IPHeader", (PyObject*) &fparser_ip_hdr_ntuple_type);

  PyStructSequence_InitType(&fparser_tcp_hdr_ntuple_type, &tcp_hdr_ntuple_desc);
  Py_INCREF(&fparser_tcp_hdr_ntuple_type);
  PyModule_AddObject(m, "TCPHeader", (PyObject*) &fparser_tcp_hdr_ntuple_type);

  PyEval_InitThreads();
}

}
