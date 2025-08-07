    for filename in check_implementation_files:
      # Move check implementation to the directory of the new module.
      filename = fileRename(filename, old_module_path, new_module_path)
      replaceInFileRegex(filename,
                         'namespace clang::tidy::' + old_module + '[^ \n]*',