    }

    result = requests.request('POST', URL + '/EndpointSecurityManager/HashManagement/OverrideHashVerdict',
                              headers=headers, cookies=cookies, data=payload, verify=USE_SSL)
