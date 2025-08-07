                              "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as s_file:
        static_config = yaml.safe_load(s_file)
