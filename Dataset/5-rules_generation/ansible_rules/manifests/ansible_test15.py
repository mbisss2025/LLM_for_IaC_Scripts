
    def html(self):
        template = jinja2.Template(USECASE_HTML_DOCUMENT_TEMPLATE)
        return template.render(
            playbook_name=self.playbook_name,