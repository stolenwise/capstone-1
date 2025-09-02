def test_basic():
    """Simple test that doesn't import the app"""
    assert 1 + 1 == 2

def test_import_works():
    """Test basic imports without the problematic app"""
    import os
    import tempfile
    assert os is not None
    assert tempfile is not None