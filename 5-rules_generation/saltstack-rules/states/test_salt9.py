      filename = self.file_to_reduce

    p = subprocess.Popen(self.get_crash_cmd(args=args, filename=filename),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)