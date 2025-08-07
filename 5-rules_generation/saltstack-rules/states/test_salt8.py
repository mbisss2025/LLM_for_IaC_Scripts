    cmd = "ps -ef | grep " + processName
    print(cmd)
    res=subprocess.getoutput(cmd)
    print(res)
    # eg. of output