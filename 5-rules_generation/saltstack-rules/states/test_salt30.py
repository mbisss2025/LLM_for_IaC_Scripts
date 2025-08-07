        args_len = len(args)
        if args_len == 0:
            g_log_file = tempfile.mktemp()
        elif len(args) == 1:
            g_log_file = args[0]