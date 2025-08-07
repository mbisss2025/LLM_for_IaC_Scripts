            for path in files_in_archive:
                if path not in self.exclude:
                    self.file.extract(path)
                    self.targets.append(path)
        else: