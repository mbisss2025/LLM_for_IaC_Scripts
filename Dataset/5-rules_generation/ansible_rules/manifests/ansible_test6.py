
    def execute_cmd(self, cmd=None):
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        output = process.communicate()[0]