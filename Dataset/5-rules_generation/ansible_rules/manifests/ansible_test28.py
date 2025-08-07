                invalid_pack_path = invalid_pack[1]
                # remove pack from index
                shutil.rmtree(invalid_pack_path)
                logging.warning(f"Deleted {invalid_pack_name} pack from {GCPConfig.INDEX_NAME} folder")
                # important to add trailing slash at the end of path in order to avoid packs with same prefix