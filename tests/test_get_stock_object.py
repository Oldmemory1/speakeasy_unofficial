from speakeasy.winenv.api.usermode.gdi32 import GDI32


def _handler() -> GDI32:
    handler = GDI32.__new__(GDI32)
    handler.handle = 0
    handler.stock_objects = {}
    return handler


def test_valid_stock_objects_have_stable_nonzero_handles() -> None:
    handler = _handler()

    handles = {
        stock_object: handler.GetStockObject(None, [stock_object]) for stock_object in sorted(GDI32.STOCK_OBJECT_TYPES)
    }

    assert all(handle != 0 for handle in handles.values())
    assert len(set(handles.values())) == len(handles)
    for stock_object, handle in handles.items():
        assert handler.GetStockObject(None, [stock_object]) == handle


def test_invalid_stock_objects_return_null() -> None:
    handler = _handler()

    assert handler.GetStockObject(None, [9]) == 0
    assert handler.GetStockObject(None, [-1]) == 0
    assert handler.GetStockObject(None, [20]) == 0
    assert handler.GetStockObject(None, [0x100000]) == 0


def test_stock_object_handles_are_deterministic_and_do_not_use_created_object_sequence() -> None:
    first = _handler()
    second = _handler()

    assert first.GetStockObject(None, [0]) == second.GetStockObject(None, [0])
    assert first.GetStockObject(None, [0]) != first.get_handle()
    assert first.GetStockObject(None, [0]) == 0x7000
