    # if release N+1 nodes are incorrectly left powered up when the release N
    # load is installed.
    shutil.rmtree(os.path.join(PLATFORM_PATH, ".keyring", to_release),
                  ignore_errors=True)
    shutil.copytree(os.path.join(PLATFORM_PATH, ".keyring", from_release),