                try:
                    os.mkdir(path)
                    os.chmod(path, 0o777)
                except BaseException:
                    pass