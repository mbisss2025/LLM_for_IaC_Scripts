    h.update(' '.join(sys.argv[2:]).encode('utf-8'))
    h.update(os.getcwd().encode('utf-8'))
    input_hash = h.hexdigest()

    # Use the hash to "uniquely" identify a reproducer path.