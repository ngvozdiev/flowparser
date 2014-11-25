import unittest
import fparser

def dummy():
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
                                flow_callback, is_file=True)
        fp.run_trace()
        self.assertEqual(9976, count[0])

if __name__ == '__main__':
    unittest.main()
