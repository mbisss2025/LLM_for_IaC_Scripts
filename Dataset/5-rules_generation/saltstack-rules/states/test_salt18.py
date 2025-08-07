        # Get the diff
        try:
            patch = requests.get(self.pr.diff_url).text
        except:
            patch = ""