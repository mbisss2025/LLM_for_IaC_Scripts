
    with open(source_path) as f:
        playbook = yaml.load(f, Loader=yamlordereddictloader.SafeLoader)

    playbook = update_replace_copy_dev(playbook)