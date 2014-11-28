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

static PyTypeObject fparser_flow_key_ntuple_type = { };
static PyStructSequence_Field flow_key_ntuple_fields[] = { { "src",
    "The source IP address of the flow" }, { "sport",
    "The source port of the transport header of the flow" }, { "dst",
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

namespace flow_info {

static PyTypeObject fparser_flow_info_ntuple_type = { };
static PyStructSequence_Field flow_info_ntuple_fields[] =
    { { "first_rx", "Timestamp of the first packet" }, { "last_rx",
        "Timestamp of the last packet" }, { "size_pkts",
        "Number of packets in the flow" }, { "size_bytes",
        "The sum of the length fields of all IP headers in the flow" }, {
        nullptr } };

static PyStructSequence_Desc flow_info_ntuple_desc = { "fparser.FlowInfo",
    nullptr, flow_info_ntuple_fields, 4 };

// Converts a flowparser::FlowKey to fparser.FlowKey
static PyObject* FromFlowInfo(const FlowInfo& info) {
  PyObject* ntuple = PyStructSequence_New(&fparser_flow_info_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0,
                            PyLong_FromUnsignedLongLong(info.first_rx));
  PyStructSequence_SET_ITEM(ntuple, 1,
                            PyLong_FromUnsignedLongLong(info.last_rx));
  PyStructSequence_SET_ITEM(ntuple, 2,
                            PyLong_FromUnsignedLongLong(info.size_pkts));
  PyStructSequence_SET_ITEM(ntuple, 3,
                            PyLong_FromUnsignedLongLong(info.size_bytes));

  return ntuple;
}

}  // namespace flow_info

// fparser.IPHeader is the Python equivalent of flowparser::IPHeader. It
// contains all fields that are tracked by flowparser for every IP packet.
namespace header {

static PyTypeObject fparser_ip_hdr_ntuple_type = { };
static PyStructSequence_Field ip_hdr_ntuple_fields[] = { { "timestamp",
    "PCAP timestamp" }, { "ttl", "TTL value" }, { "length", "IP length" }, {
    "id", "IP id" }, { nullptr } };

static PyStructSequence_Desc ip_hdr_ntuple_desc = { "fparser.IPHeader", nullptr,
    ip_hdr_ntuple_fields, 4 };

// Constructs a new fparser.IPHeader from a flowparser::IPHeader instance.
static PyObject* FromHeader(const IPHeader& ip) {
  PyObject* ntuple = PyStructSequence_New(&fparser_ip_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0,
                            PyLong_FromUnsignedLongLong(ip.timestamp));
  PyStructSequence_SET_ITEM(ntuple, 1, PyInt_FromLong(ip.ttl));
  PyStructSequence_SET_ITEM(ntuple, 2, PyInt_FromLong(ip.length));
  PyStructSequence_SET_ITEM(ntuple, 3, PyInt_FromLong(ip.id));

  return ntuple;
}

static PyTypeObject fparser_tcp_hdr_ntuple_type = { };
static PyStructSequence_Field tcp_hdr_ntuple_fields[] = { { "ip", "IP header" },
    { "seq", "TCP sequence number" }, { "ack", "TCP ack number" }, { "win",
        "TCP window" }, { "flags", "TCP flags" }, { nullptr } };

static PyStructSequence_Desc tcp_hdr_ntuple_desc = { "fparser.TCPHeader",
    nullptr, tcp_hdr_ntuple_fields, 5 };

static PyObject* TCPFromHeader(const IPHeader& ip, const TCPHeader& tcp) {
  PyObject* ntuple = PyStructSequence_New(&fparser_tcp_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0, FromHeader(ip));
  PyStructSequence_SET_ITEM(ntuple, 1, PyLong_FromUnsignedLongLong(tcp.seq));
  PyStructSequence_SET_ITEM(ntuple, 2, PyLong_FromUnsignedLongLong(tcp.ack));
  PyStructSequence_SET_ITEM(ntuple, 3, PyInt_FromLong(tcp.win));
  PyStructSequence_SET_ITEM(ntuple, 4, PyInt_FromLong(tcp.flags));

  return ntuple;
}

static PyTypeObject fparser_udp_hdr_ntuple_type = { };
static PyStructSequence_Field udp_hdr_ntuple_fields[] = { { "ip", "IP header" },
    { nullptr } };

static PyStructSequence_Desc udp_hdr_ntuple_desc = { "fparser.UDPHeader",
    nullptr, udp_hdr_ntuple_fields, 1 };

static PyObject* UDPFromHeader(const IPHeader& ip) {
  PyObject* ntuple = PyStructSequence_New(&fparser_udp_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0, FromHeader(ip));

  return ntuple;
}

static PyTypeObject fparser_icmp_hdr_ntuple_type = { };
static PyStructSequence_Field icmp_hdr_ntuple_fields[] = {
    { "ip", "IP header" }, { "type", "ICMP type" }, { "code", "ICMP code" }, {
        nullptr } };

static PyStructSequence_Desc icmp_hdr_ntuple_desc = { "fparser.ICMPHeader",
    nullptr, icmp_hdr_ntuple_fields, 3 };

static PyObject* ICMPFromHeader(const IPHeader& ip, const ICMPHeader& icmp) {
  PyObject* ntuple = PyStructSequence_New(&fparser_icmp_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0, FromHeader(ip));
  PyStructSequence_SET_ITEM(ntuple, 1, PyInt_FromLong(icmp.type));
  PyStructSequence_SET_ITEM(ntuple, 2, PyInt_FromLong(icmp.code));

  return ntuple;
}

static PyTypeObject fparser_unknown_hdr_ntuple_type = { };
static PyStructSequence_Field unknown_hdr_ntuple_fields[] = { { "ip",
    "IP header" }, { nullptr } };

static PyStructSequence_Desc unknown_hdr_ntuple_desc = {
    "fparser.UnknownHeader", nullptr, unknown_hdr_ntuple_fields, 1 };

static PyObject* UnknownFromHeader(const IPHeader& ip) {
  PyObject* ntuple = PyStructSequence_New(&fparser_unknown_hdr_ntuple_type);
  PyStructSequence_SET_ITEM(ntuple, 0, FromHeader(ip));

  return ntuple;
}

}  // namespace header

// All members of this namespace are templatized for the different flow types.
// This is ugly, but it is better than repeating the same code N times.
namespace flow {

// The main struct that holds a flow, its key and an iterator as unique
// pointers.
template<typename T, typename I>
struct PythonFlow {
  PyObject_HEAD

  uint64_t size_pkts;  // number of packets in the flow
  std::unique_ptr<const T> flow;
  std::unique_ptr<const FlowKey> key;
  std::unique_ptr<I> it;  // iterator
};

typedef PythonFlow<TCPFlow, TCPFlowIterator> PythonTCPFlow;
typedef PythonFlow<UDPFlow, FlowIterator> PythonUDPFlow;
typedef PythonFlow<ICMPFlow, ICMPFlowIterator> PythonICMPFlow;
typedef PythonFlow<UnknownFlow, FlowIterator> PythonUnknownFlow;

// The flow's iterator is just the flow object itself - the it field is
// populated with the most recent iterator.
static PyObject* PythonFlowIter(PyObject* self) {
  Py_INCREF(self);
  return self;
}

// A wrapper class that has only static methods
template<typename T>
class StaticWrapper {
 public:
  // Frees a PythonTCPFlow
  static void PythonFlowDealloc(T* fparser_flow) {
    fparser_flow->it.~unique_ptr();
    fparser_flow->flow.~unique_ptr();
    fparser_flow->key.~unique_ptr();

    fparser_flow->ob_type->tp_free((PyObject *) fparser_flow);
  }

  // Returns the flow's id.
  static PyObject* PythonFlowGetId(PyObject* self) {
    const T* py_flow = (T*) self;
    const FlowKey& key = *py_flow->key;

    return flow_key::FromFlowKey(key);
  }

  // Returns the flow's info.
  static PyObject* PythonFlowGetInfo(PyObject* self) {
    const T* py_flow = (T*) self;
    const FlowInfo info = py_flow->flow->GetInfo();

    return flow_info::FromFlowInfo(info);
  }

  // Returns the number of packets in the flow.
  static Py_ssize_t PythonFlowGetLen(PyObject* self) {
    const T* py_flow = (T*) self;
    return (Py_ssize_t) py_flow->size_pkts;
  }
};

typedef StaticWrapper<PythonTCPFlow> TCPMethods;
typedef StaticWrapper<PythonUDPFlow> UDPMethods;
typedef StaticWrapper<PythonICMPFlow> ICMPMethods;
typedef StaticWrapper<PythonUnknownFlow> UnknownMethods;

// Gets the next object from the iterator, or raises a StopIteration exception
// and resets the iterator.
static PyObject* PythonTCPFlowIternext(PyObject* self) {
  PythonTCPFlow* py_flow = (PythonTCPFlow*) self;

  IPHeader ip_header = { };
  TCPHeader transport_header = { };
  bool has_more = py_flow->it->Next(&ip_header, &transport_header);
  if (!has_more) {
    py_flow->it = std::make_unique<TCPFlowIterator>(*py_flow->flow);
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
  }

  return header::TCPFromHeader(ip_header, transport_header);
}

static PyObject* PythonICMPFlowIternext(PyObject* self) {
  PythonICMPFlow* py_flow = (PythonICMPFlow*) self;

  IPHeader ip_header = { };
  ICMPHeader transport_header = { };
  bool has_more = py_flow->it->Next(&ip_header, &transport_header);
  if (!has_more) {
    py_flow->it = std::make_unique<ICMPFlowIterator>(*py_flow->flow);
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
  }

  return header::ICMPFromHeader(ip_header, transport_header);
}

static PyObject* PythonUDPFlowIternext(PyObject* self) {
  PythonUDPFlow* py_flow = (PythonUDPFlow*) self;

  IPHeader ip_header = { };
  bool has_more = py_flow->it->Next(&ip_header);
  if (!has_more) {
    py_flow->it = std::make_unique<FlowIterator>(*py_flow->flow);
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
  }

  return header::UDPFromHeader(ip_header);
}

static PyObject* PythonUnknownFlowIternext(PyObject* self) {
  PythonUnknownFlow* py_flow = (PythonUnknownFlow*) self;

  IPHeader ip_header = { };
  bool has_more = py_flow->it->Next(&ip_header);
  if (!has_more) {
    py_flow->it = std::make_unique<FlowIterator>(*py_flow->flow);
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
  }

  return header::UnknownFromHeader(ip_header);
}

PyMethodDef python_tcp_flow_methods[] = { { "get_id",
    (PyCFunction) TCPMethods::PythonFlowGetId, METH_NOARGS,
    "Returns the flow's id" }, { "get_info",
    (PyCFunction) TCPMethods::PythonFlowGetInfo, METH_NOARGS,
    "Returns the flow's id" }, { nullptr } };

PySequenceMethods python_tcp_flow_sequence_methods = {
    TCPMethods::PythonFlowGetLen, /* sq_length */
};

PyMethodDef python_udp_flow_methods[] = { { "get_id",
    (PyCFunction) UDPMethods::PythonFlowGetId, METH_NOARGS,
    "Returns the flow's id" }, { "get_info",
    (PyCFunction) UDPMethods::PythonFlowGetInfo, METH_NOARGS,
    "Returns the flow's id" }, { nullptr } };

PySequenceMethods python_udp_flow_sequence_methods = {
    UDPMethods::PythonFlowGetLen, /* sq_length */
};

PyMethodDef python_icmp_flow_methods[] = { { "get_id",
    (PyCFunction) ICMPMethods::PythonFlowGetId, METH_NOARGS,
    "Returns the flow's id" }, { "get_info",
    (PyCFunction) ICMPMethods::PythonFlowGetInfo, METH_NOARGS,
    "Returns the flow's id" }, { nullptr } };

PySequenceMethods python_icmp_flow_sequence_methods = {
    ICMPMethods::PythonFlowGetLen, /* sq_length */
};

PyMethodDef python_unknown_flow_methods[] = { { "get_id",
    (PyCFunction) UnknownMethods::PythonFlowGetId, METH_NOARGS,
    "Returns the flow's id" }, { "get_info",
    (PyCFunction) UnknownMethods::PythonFlowGetInfo, METH_NOARGS,
    "Returns the flow's id" }, { nullptr } };

PySequenceMethods python_unknown_flow_sequence_methods = {
    UnknownMethods::PythonFlowGetLen, /* sq_length */
};

// Boilerplate for the type.
PyTypeObject python_tcp_flow_type = { PyObject_HEAD_INIT(nullptr) 0, /*ob_size*/
"fparser.TCPFlow", /*tp_name*/
sizeof(PythonTCPFlow), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) TCPMethods::PythonFlowDealloc, /*tp_dealloc*/
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
PythonFlowIter, /* tp_iter: __iter__() method */
PythonTCPFlowIternext, /* tp_iternext: next() method */
(PyMethodDef*) python_tcp_flow_methods /* tp_methods */
};

PyTypeObject python_udp_flow_type = { PyObject_HEAD_INIT(nullptr) 0, /*ob_size*/
"fparser.UDPFlow", /*tp_name*/
sizeof(PythonUDPFlow), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) UDPMethods::PythonFlowDealloc, /*tp_dealloc*/
0, /*tp_print*/
0, /*tp_getattr*/
0, /*tp_setattr*/
0, /*tp_compare*/
0, /*tp_repr*/
0, /*tp_as_number*/
&python_udp_flow_sequence_methods, /*tp_as_sequence*/
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
"Internal fparser UDP flow object.", /* tp_doc */
0, /* tp_traverse */
0, /* tp_clear */
0, /* tp_richcompare */
0, /* tp_weaklistoffset */
PythonFlowIter, /* tp_iter: __iter__() method */
PythonUDPFlowIternext, /* tp_iternext: next() method */
(PyMethodDef*) python_udp_flow_methods /* tp_methods */
};

PyTypeObject python_icmp_flow_type = { PyObject_HEAD_INIT(nullptr) 0, /*ob_size*/
"fparser.ICMPFlow", /*tp_name*/
sizeof(PythonICMPFlow), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) ICMPMethods::PythonFlowDealloc, /*tp_dealloc*/
0, /*tp_print*/
0, /*tp_getattr*/
0, /*tp_setattr*/
0, /*tp_compare*/
0, /*tp_repr*/
0, /*tp_as_number*/
&python_icmp_flow_sequence_methods, /*tp_as_sequence*/
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
"Internal fparser ICMP flow object.", /* tp_doc */
0, /* tp_traverse */
0, /* tp_clear */
0, /* tp_richcompare */
0, /* tp_weaklistoffset */
PythonFlowIter, /* tp_iter: __iter__() method */
PythonICMPFlowIternext, /* tp_iternext: next() method */
(PyMethodDef*) python_icmp_flow_methods /* tp_methods */
};

PyTypeObject python_unknown_flow_type = { PyObject_HEAD_INIT(nullptr) 0, /*ob_size*/
"fparser.UnknownFlow", /*tp_name*/
sizeof(PythonUnknownFlow), /*tp_basicsize*/
0, /*tp_itemsize*/
(destructor) UnknownMethods::PythonFlowDealloc, /*tp_dealloc*/
0, /*tp_print*/
0, /*tp_getattr*/
0, /*tp_setattr*/
0, /*tp_compare*/
0, /*tp_repr*/
0, /*tp_as_number*/
&python_unknown_flow_sequence_methods, /*tp_as_sequence*/
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
"Internal fparser UNKNOWN flow object.", /* tp_doc */
0, /* tp_traverse */
0, /* tp_clear */
0, /* tp_richcompare */
0, /* tp_weaklistoffset */
PythonFlowIter, /* tp_iter: __iter__() method */
PythonUnknownFlowIternext, /* tp_iternext: next() method */
(PyMethodDef*) python_unknown_flow_methods /* tp_methods */
};

// Constructs a new PythonTCPFlow from a combination of a FlowKey and a TCPFlow.
// This function will take ownership of the TCPFlow object and store it as a
// const unique pointer, guaranteeing that the flow will not be modified once it
// is handed off to Python.
static PythonTCPFlow* FromTCPFlow(const FlowKey& key,
                                  std::unique_ptr<TCPFlow> flow) {
  PythonTCPFlow* py_flow;

  py_flow = PyObject_New(PythonTCPFlow, (PyTypeObject* ) &python_tcp_flow_type);
  if (!py_flow) {
    return nullptr;
  }

  py_flow->size_pkts = flow->GetInfo().size_pkts;
  new (&py_flow->flow) std::unique_ptr<const TCPFlow>(std::move(flow));
  new (&py_flow->key) std::unique_ptr<const FlowKey>(new FlowKey(key));
  new (&py_flow->it) std::unique_ptr<TCPFlowIterator>(
      new TCPFlowIterator(*py_flow->flow));

  return py_flow;
}

static PythonUDPFlow* FromUDPFlow(const FlowKey& key,
                                  std::unique_ptr<UDPFlow> flow) {
  PythonUDPFlow* py_flow;

  py_flow = PyObject_New(PythonUDPFlow, (PyTypeObject* ) &python_udp_flow_type);
  if (!py_flow) {
    return nullptr;
  }

  py_flow->size_pkts = flow->GetInfo().size_pkts;
  new (&py_flow->flow) std::unique_ptr<const UDPFlow>(std::move(flow));
  new (&py_flow->key) std::unique_ptr<const FlowKey>(new FlowKey(key));
  new (&py_flow->it) std::unique_ptr<FlowIterator>(
      new FlowIterator(*py_flow->flow));

  return py_flow;
}

static PythonICMPFlow* FromICMPFlow(const FlowKey& key,
                                    std::unique_ptr<ICMPFlow> flow) {
  PythonICMPFlow* py_flow;

  py_flow = PyObject_New(PythonICMPFlow,
                         (PyTypeObject* ) &python_icmp_flow_type);
  if (!py_flow) {
    return nullptr;
  }

  py_flow->size_pkts = flow->GetInfo().size_pkts;
  new (&py_flow->flow) std::unique_ptr<const ICMPFlow>(std::move(flow));
  new (&py_flow->key) std::unique_ptr<const FlowKey>(new FlowKey(key));
  new (&py_flow->it) std::unique_ptr<ICMPFlowIterator>(
      new ICMPFlowIterator(*py_flow->flow));

  return py_flow;
}

static PythonUnknownFlow* FromUnknownFlow(const FlowKey& key,
                                          std::unique_ptr<UnknownFlow> flow) {
  PythonUnknownFlow* py_flow;

  py_flow = PyObject_New(PythonUnknownFlow,
                         (PyTypeObject* ) &python_unknown_flow_type);
  if (!py_flow) {
    return nullptr;
  }

  py_flow->size_pkts = flow->GetInfo().size_pkts;
  new (&py_flow->flow) std::unique_ptr<const UnknownFlow>(std::move(flow));
  new (&py_flow->key) std::unique_ptr<const FlowKey>(new FlowKey(key));
  new (&py_flow->it) std::unique_ptr<FlowIterator>(
      new FlowIterator(*py_flow->flow));

  return py_flow;
}

}  // namespace flow

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

static void OffloadError(const PythonFlowParser* py_parser,
                         const std::string& message) {
  PyGILState_STATE d_gstate;
  PyObject* arglist;
  PyObject* result;

  d_gstate = PyGILState_Ensure();

  arglist = Py_BuildValue("(s)", message.c_str());
  result = PyObject_CallObject(py_parser->error_callback, arglist);
  Py_DECREF(arglist);

  if (result == nullptr) {
    PyErr_Print();
  }

  Py_XDECREF(result);
  PyGILState_Release(d_gstate);
}

template<typename T>
static void OffloadFlowToCallback(const PythonFlowParser* py_parser,
                                  const FlowKey& key, T* flow) {
  PyGILState_STATE d_gstate;
  PyObject* arglist;
  PyObject* result;

  if (flow == nullptr) {
    return;
  }

  d_gstate = PyGILState_Ensure();

  PyObject* python_flow_key = flow_key::FromFlowKey(key);
  if (python_flow_key == nullptr) {
    return;
  }

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
  flow::PythonTCPFlow* py_flow = flow::FromTCPFlow(key, std::move(flow));
  OffloadFlowToCallback<flow::PythonTCPFlow>(py_parser, key, py_flow);
}

// Offloads a single UDP flow to the flow callback.
static void PythonFlowParserUDPFlowOffload(PythonFlowParser* py_parser,
                                           const FlowKey& key,
                                           std::unique_ptr<UDPFlow> flow) {
  flow::PythonUDPFlow* py_flow = flow::FromUDPFlow(key, std::move(flow));
  OffloadFlowToCallback<flow::PythonUDPFlow>(py_parser, key, py_flow);
}

// Offloads a single ICMP flow to the flow callback.
static void PythonFlowParserICMPFlowOffload(PythonFlowParser* py_parser,
                                            const FlowKey& key,
                                            std::unique_ptr<ICMPFlow> flow) {
  flow::PythonICMPFlow* py_flow = flow::FromICMPFlow(key, std::move(flow));
  OffloadFlowToCallback<flow::PythonICMPFlow>(py_parser, key, py_flow);
}

// Offloads a single unknown flow to the flow callback.
static void PythonFlowParserUnknownFlowOffload(
    PythonFlowParser* py_parser, const FlowKey& key,
    std::unique_ptr<UnknownFlow> flow) {
  flow::PythonUnknownFlow* py_flow = flow::FromUnknownFlow(key,
                                                           std::move(flow));
  OffloadFlowToCallback<flow::PythonUnknownFlow>(py_parser, key, py_flow);
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

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "sO|isiiO", argnames, &source,
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

  if (hard_mem_limit_mb > 0 && soft_mem_limit_mb < 0) {
    PyErr_SetString(PyExc_TypeError, "Bad memory limits");
    return nullptr;
  }

  self = (PythonFlowParser*) type->tp_alloc(type, 0);

  Py_INCREF(flow_callback);
  self->flow_callback = flow_callback;

  FlowParserConfig cfg;

  if (is_file) {
    cfg.OfflineTrace(std::string(source));
  } else {
    cfg.OnlineTrace(std::string(source));
  }

  if (error_callback) {
    Py_INCREF(error_callback);
    self->error_callback = error_callback;

    cfg.InfoCallback([self] (const std::string& message) {
      OffloadError(self, message);
    });

    cfg.BadStatusCallback([self] (Status status) {
      OffloadError(self, status.ToString());
    });
  }

  cfg.TCPCallback([self] (const FlowKey& key, unique_ptr<TCPFlow> flow) {
    PythonFlowParserTCPFlowOffload(self, key, std::move(flow));
  });

  cfg.UDPCallback([self] (const FlowKey& key, unique_ptr<UDPFlow> flow) {
    PythonFlowParserUDPFlowOffload(self, key, std::move(flow));
  });

  cfg.ICMPCallback([self] (const FlowKey& key, unique_ptr<ICMPFlow> flow) {
    PythonFlowParserICMPFlowOffload(self, key, std::move(flow));
  });

  cfg.UnknownCallback(
      [self] (const FlowKey& key, unique_ptr<UnknownFlow> flow) {
        PythonFlowParserUnknownFlowOffload(self, key, std::move(flow));
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

  Py_BEGIN_ALLOW_THREADS

  Status status = py_parser->flow_parser->RunTrace();
  if (!status.ok()) {
    Py_BLOCK_THREADS
    PyErr_SetString(PyExc_IOError, status.ToString().c_str());
    Py_UNBLOCK_THREADS
    return nullptr;
  }

  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

// Return a (first_rx, last_rx) tuple
static PyObject* PythonFlowParserTimestampRange(PyObject* self) {
  const PythonFlowParser* py_parser = (PythonFlowParser*) self;

  uint64_t first_rx = py_parser->flow_parser->first_rx();
  uint64_t last_rx = py_parser->flow_parser->last_rx();

  return Py_BuildValue("(KK)", first_rx, last_rx);
}

// Methods of the PythonFlowParser object.
static PyMethodDef python_flow_parser_methods[] = { { "run_trace",
    (PyCFunction) PythonFlowParserRunTrace, METH_NOARGS,
    "Blocks and traces until source is exhausted" }, { "timestamp_range",
    (PyCFunction) PythonFlowParserTimestampRange, METH_NOARGS,
    "Returns a tuple with the first and the last timestamp seen" }, { nullptr,
    nullptr, 0, nullptr } };

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
using flowparser::python_shim::flow::python_tcp_flow_type;
using flowparser::python_shim::flow::python_udp_flow_type;
using flowparser::python_shim::flow::python_icmp_flow_type;
using flowparser::python_shim::flow::python_unknown_flow_type;

using flowparser::python_shim::flow_key::fparser_flow_key_ntuple_type;
using flowparser::python_shim::flow_key::flow_key_ntuple_desc;

using flowparser::python_shim::flow_info::fparser_flow_info_ntuple_type;
using flowparser::python_shim::flow_info::flow_info_ntuple_desc;

using flowparser::python_shim::header::fparser_ip_hdr_ntuple_type;
using flowparser::python_shim::header::ip_hdr_ntuple_desc;

using flowparser::python_shim::header::fparser_tcp_hdr_ntuple_type;
using flowparser::python_shim::header::tcp_hdr_ntuple_desc;

using flowparser::python_shim::header::fparser_icmp_hdr_ntuple_type;
using flowparser::python_shim::header::icmp_hdr_ntuple_desc;

using flowparser::python_shim::header::fparser_udp_hdr_ntuple_type;
using flowparser::python_shim::header::udp_hdr_ntuple_desc;

using flowparser::python_shim::header::fparser_unknown_hdr_ntuple_type;
using flowparser::python_shim::header::unknown_hdr_ntuple_desc;

PyMODINIT_FUNC initfparser(void) {
  PyObject *m;

  m = Py_InitModule("fparser", fparser_module_methods);
  if (m == nullptr) {
    return;
  }

  if (PyType_Ready(&python_flow_parser_type) < 0) {
    return;
  }

  if (PyType_Ready((PyTypeObject*) &python_tcp_flow_type) < 0) {
    return;
  }

  if (PyType_Ready((PyTypeObject*) &python_udp_flow_type) < 0) {
    return;
  }

  if (PyType_Ready((PyTypeObject*) &python_icmp_flow_type) < 0) {
    return;
  }

  if (PyType_Ready((PyTypeObject*) &python_unknown_flow_type) < 0) {
    return;
  }

  Py_INCREF(&python_flow_parser_type);
  PyModule_AddObject(m, "FlowParser", (PyObject*) &python_flow_parser_type);

  Py_INCREF(&python_tcp_flow_type);
  PyModule_AddObject(m, "TCPFlow", (PyObject *) &python_tcp_flow_type);

  Py_INCREF(&python_udp_flow_type);
  PyModule_AddObject(m, "UDPFlow", (PyObject *) &python_udp_flow_type);

  Py_INCREF(&python_icmp_flow_type);
  PyModule_AddObject(m, "ICMPFlow", (PyObject *) &python_icmp_flow_type);

  Py_INCREF(&python_unknown_flow_type);
  PyModule_AddObject(m, "UnknownFlow", (PyObject *) &python_unknown_flow_type);

  PyStructSequence_InitType(&fparser_flow_key_ntuple_type,
                            &flow_key_ntuple_desc);
  Py_INCREF(&fparser_flow_key_ntuple_type);
  PyModule_AddObject(m, "FlowKey", (PyObject*) &fparser_flow_key_ntuple_type);

  PyStructSequence_InitType(&fparser_flow_info_ntuple_type,
                            &flow_info_ntuple_desc);
  Py_INCREF(&fparser_flow_info_ntuple_type);
  PyModule_AddObject(m, "FlowInfo", (PyObject*) &fparser_flow_info_ntuple_type);

  PyStructSequence_InitType(&fparser_ip_hdr_ntuple_type, &ip_hdr_ntuple_desc);
  Py_INCREF(&fparser_ip_hdr_ntuple_type);
  PyModule_AddObject(m, "IPHeader", (PyObject*) &fparser_ip_hdr_ntuple_type);

  PyStructSequence_InitType(&fparser_tcp_hdr_ntuple_type, &tcp_hdr_ntuple_desc);
  Py_INCREF(&fparser_tcp_hdr_ntuple_type);
  PyModule_AddObject(m, "TCPHeader", (PyObject*) &fparser_tcp_hdr_ntuple_type);

  PyStructSequence_InitType(&fparser_udp_hdr_ntuple_type, &udp_hdr_ntuple_desc);
  Py_INCREF(&fparser_udp_hdr_ntuple_type);
  PyModule_AddObject(m, "UDPHeader", (PyObject*) &fparser_udp_hdr_ntuple_type);

  PyStructSequence_InitType(&fparser_unknown_hdr_ntuple_type,
                            &unknown_hdr_ntuple_desc);
  Py_INCREF(&fparser_unknown_hdr_ntuple_type);
  PyModule_AddObject(m, "UnknownHeader",
                     (PyObject*) &fparser_unknown_hdr_ntuple_type);

  PyStructSequence_InitType(&fparser_icmp_hdr_ntuple_type,
                            &icmp_hdr_ntuple_desc);
  Py_INCREF(&fparser_icmp_hdr_ntuple_type);
  PyModule_AddObject(m, "ICMPHeader",
                     (PyObject*) &fparser_icmp_hdr_ntuple_type);

  if (!PyEval_ThreadsInitialized()) {
    PyEval_InitThreads();
  }
}

}
