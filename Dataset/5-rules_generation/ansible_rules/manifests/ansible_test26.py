    requests_mock.post(url3, json=item_purchase_response[3])

    api4 = integration.MESSAGE_API.format(API_KEY=API_KEY)
    url4 = f'{integration.BASE_URL}/{api4}'
    requests_mock.post(url4, json=item_purchase_response[4])