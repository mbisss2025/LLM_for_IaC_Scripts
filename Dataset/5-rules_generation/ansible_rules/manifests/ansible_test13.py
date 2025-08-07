        pack_metadata = get_pack_metadata(pack)
        pack_name = pack_metadata.get('name')
        new_packs_release_notes[pack_name] = get_pack_entities(pack)
        new_packs_metadata[pack_name] = pack_metadata
