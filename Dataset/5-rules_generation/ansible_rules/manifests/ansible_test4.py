    container_engine_type = 'podman' if is_redhat_instance(ip) else 'docker'
    try:
        check_output(
            f'ssh {SSH_USER}@{ip} cd /home/demisto && sudo -u demisto {container_engine_type} '
            f'login --username {docker_username} --password-stdin'.split(),