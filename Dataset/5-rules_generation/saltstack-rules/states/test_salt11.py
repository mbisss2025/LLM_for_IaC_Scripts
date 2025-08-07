    # mkdir fails with EAGAIN/EWOULDBLOCK, see internal Google bug,
    # b/289311228.)
    local_dir_hash = hashlib.sha1(local_dir.encode()).hexdigest()
    remote_dir = f"{REMOTE_BASE_DIR}/run-{local_dir_hash}/{os.path.basename(local_dir)}"
    sync_test_dir(local_dir, remote_dir)