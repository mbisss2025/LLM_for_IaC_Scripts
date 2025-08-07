  for mandatory in mandatory_list:
    wrap_h = os.path.join(gen_dir, 'asm', mandatory)
    with open(wrap_h, 'w') as f:
      f.write('#include <asm-generic/%s>\n' % mandatory)
  return error_count