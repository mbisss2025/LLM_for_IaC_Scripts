    code      = literal_block.astext()
    hashobj   = code.encode('utf-8') #  str(node.attributes)
    fname     = path.join('%s-%s' % (srclang, sha1(hashobj).hexdigest()))

    tmp_fname = path.join(