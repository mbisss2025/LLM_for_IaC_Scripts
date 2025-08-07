                    self.check_no_output = True
                    return
                match = re.search(
                    "{}: num_threads=([0-9]+) (.*)$".format(self.prefix), line
                )