import unittest
import fparser

def dummy(error):
    pass

# Tests various failure modes during initialization
class TestFlowParserInit(unittest.TestCase):
    def test_bad_init_only_src(self):
        with self.assertRaises(TypeError):
            # Need to have at least source and callback
            fp = fparser.FlowParser('some_src')

    def test_bad_init_non_callable(self):
        with self.assertRaises(TypeError):
            # The flow callback should be a callable object
            fp = fparser.FlowParser('some_src', 'not a function')

    def test_bad_init_error_non_callable(self):
        with self.assertRaises(TypeError):
            # The error callback should be a callable object
            fp = fparser.FlowParser('some_src', dummy, 
                                    error_callback='not a function')

    def test_bad_init_memory_limits(self):
        with self.assertRaises(TypeError):
            # Wrong memory limits - lower is larger than upper
            fp = fparser.FlowParser('some_src', dummy, 
                                    hard_mem_limit=10, soft_mem_limit=100)

    def test_bad_init_only_low_mem_limit(self):
        with self.assertRaises(TypeError):
            # Wrong memory limits - only lower specified
            fp = fparser.FlowParser('some_src', dummy, 
                                    soft_mem_limit=100)

    def test_bad_init_only_up_mem_limit(self):
        with self.assertRaises(TypeError):
            # Wrong memory limits - only upper specified
            fp = fparser.FlowParser('some_src', dummy, 
                                    hard_mem_limit=10)
    
    def test_bad_file_source(self):
        with self.assertRaises(IOError):
            fp = fparser.FlowParser('some_bogus_source_file', dummy, is_file=True)
            fp.run_trace()

    def test_bad_iface_source(self):
        with self.assertRaises(IOError):
            fp = fparser.FlowParser('some_bogus_source_iface', dummy)
            fp.run_trace()

class TestFlowParser(unittest.TestCase):
    def setUp(self):
        self.filename = '../test_data/output_dump'

    def test_total_pkt_count(self):
        count = [0]
        def flow_callback(key, flow):
            for pkt in flow:
                count[0] += 1

        fp = fparser.FlowParser(self.filename, 
                                flow_callback, is_file=True, error_callback=dummy)
        fp.run_trace()
        self.assertEqual(9976, count[0])

    def test_find_flow(self):
        # Will try to find a single TCP flow 181.175.235.116:80 -> 71.126.3.230:65470
        len_model = [1500, 1500, 1500, 1500, 1500, 1500, 1500,
                     1500, 684, 652]
        id_model = [42057, 42058, 42059, 42060, 42061, 42062,
                    42063, 42064, 42065, 42066]
        seq_model = [1, 1449, 2897, 4345, 5793, 7241, 8689,
                     10137, 11585, 12217]
        seq_relative_to = 2585150390
        flags_model = [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                       0x10, 0x18, 0x18]
        ack_model = [438222783] * 10
        ttl_model = [89] * 10
        win_model = [404] * 10

        pkts = []
        def flow_callback(key, flow):
            if not isinstance(flow, fparser.TCPFlow):
                return

            if (key.src == '181.175.235.116' and key.dst == '71.126.3.230' and 
                key.sport == 80 and key.dport == 65470):
                for pkt in flow:
                    pkts.append(pkt)

        fp = fparser.FlowParser(self.filename, 
                                flow_callback, is_file=True, error_callback=dummy)
        fp.run_trace()
        self.assertEqual(10, len(pkts))

        for i in range(10):
            self.assertEqual(pkts[i].ip.length, len_model[i])
            self.assertEqual(pkts[i].ip.id, id_model[i])
            self.assertEqual(pkts[i].ip.ttl, ttl_model[i])
            self.assertEqual(pkts[i].seq, seq_relative_to + seq_model[i])
            self.assertEqual(pkts[i].win, win_model[i])
            self.assertEqual(pkts[i].ack, ack_model[i])
            self.assertEqual(pkts[i].flags, flags_model[i])

if __name__ == '__main__':
    unittest.main()
