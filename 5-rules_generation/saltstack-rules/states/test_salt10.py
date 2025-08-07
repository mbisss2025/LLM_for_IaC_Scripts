    # Run GN command with --dotfile= and --root= added.
    cmd = [gn] + extra_args + sys.argv[1:]
    sys.exit(subprocess.call(cmd))

