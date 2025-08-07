   tf.saved_model.save(module, path, signatures=action)
   output_spec_path = get_output_spec_path(path)
   with open(output_spec_path, 'w') as f:
     print(f'Writing output spec to {output_spec_path}.')
     f.write(POLICY_OUTPUT_SPEC)