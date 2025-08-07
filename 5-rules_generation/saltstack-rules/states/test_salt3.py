        try:
            exception = None
            result = eval(check_expr, {"data":data})
        except Exception:
            result = False