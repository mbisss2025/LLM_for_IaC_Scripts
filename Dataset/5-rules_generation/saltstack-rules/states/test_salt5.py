  for module_name in args.modules:
    modules.append(
        importlib.import_module(module_name,
                                package="mlir.dialects.linalg.opdsl"))
  for i, file_path in enumerate(args.file or []):