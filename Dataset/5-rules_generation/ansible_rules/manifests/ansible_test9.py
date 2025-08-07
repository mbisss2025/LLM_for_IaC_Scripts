
    url = 'https://protect.cylance.com/Reports/ThreatDataReportV1/indicators/' + demisto.args()['token']
    res = requests.request('GET', url, verify=USE_SSL)
    filename = 'Indicators_Report.csv'
    demisto.results(fileResult(filename, res.content))