        full = os.path.join(EXAMPLE_DIR, self.path)
        py = 'example.py'
        shutil.copyfile(os.path.join(full, py),
                        os.path.join(dist_path, INSTALL_BIN_DIR, 'python', py))
