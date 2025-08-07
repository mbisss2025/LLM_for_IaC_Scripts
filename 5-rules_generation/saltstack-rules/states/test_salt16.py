    default=[],
    action="append",
    type=lambda x: re.compile(b(x)),
    help="regex to match, with line numbers captured in ().",
)