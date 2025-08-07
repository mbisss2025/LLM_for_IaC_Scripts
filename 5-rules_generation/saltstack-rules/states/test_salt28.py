    if verbose:
        print(args)
    tmpname = tempfile.mktemp()
    out = open(tmpname, 'w')
    ret = 255