    destination_dir_full_path = os.path.abspath(pargs.destination_dir)
    logging.info('Using {}'.format(pyg_full_path))
    output = mk_genfile_common.mk_hpp_from_pyg(pyg_full_path, destination_dir_full_path)
    logging.info('Generated "{}"'.format(output))
    return 0