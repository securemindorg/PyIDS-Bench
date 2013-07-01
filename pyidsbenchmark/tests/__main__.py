import unittest
import test.unit_tests

suite = unittest.TestLoader().loadTestsFromModule(test.unit_tests)

unittest.TextTestRunner().run(suite)
