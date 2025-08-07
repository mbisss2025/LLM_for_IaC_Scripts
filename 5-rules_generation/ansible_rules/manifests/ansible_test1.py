            with open(src_file, "r") as src:
                try:
                    src_data = yaml.load(src, Loader=yaml.Loader)
                except Exception as e:
                    LOG.error("Failed to load %s. Error %s" % (src_file, e))