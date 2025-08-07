        playbooks_root, upgrade_script, to_release)

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()