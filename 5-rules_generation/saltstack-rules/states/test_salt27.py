        args_len = len(args)
        if args_len == 0:
            log_file = tempfile.mktemp()
        elif len(args) == 1:
            log_file = args[0]