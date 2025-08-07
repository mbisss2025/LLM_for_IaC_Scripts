
    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/ip_command.json')