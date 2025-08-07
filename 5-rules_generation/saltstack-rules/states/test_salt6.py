    """

    p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    stdout, stderr = p.communicate()
    stdout, stderr = stdout.decode(), stderr.decode()