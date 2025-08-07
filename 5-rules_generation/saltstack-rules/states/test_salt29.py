
def pull_from_device(path):
    tmp = tempfile.mktemp()
    adb(['pull', path, tmp], 5, 60)
    text = open(tmp, 'r').read()