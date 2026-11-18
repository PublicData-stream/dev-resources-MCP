"""Enable the candidate's bounded startup readiness in the fresh assessment."""

ASSESSMENT_HELPER_PATH = 'deploy/diagnostics/npm_assessment.py'
ASSESSMENT_HELPER_SHA256 = 'd45816e73bd3f9f1082ee131aa9f687c543e9d7f1482131746c373a285b25fd3'


def patch_assessment(text: str) -> str:
    """Transform a fresh copy of the fifth-cycle assessment at render time."""
    replacements = (
        (
            "    pod=helper.build_assessment_pod(template,image,helper.Selection(JOB),POD,'devres',ASSESSMENT_SCOPE)\n",
            "    pod=helper.build_assessment_pod(template,image,helper.Selection(JOB),POD,'devres',ASSESSMENT_SCOPE,\n"
            "                                    connect_readiness=True)\n",
        ),
        (
            """    need(len(body)<=4*1024**2 and hashlib.sha256(body).hexdigest()==manifest[name],
         'assessment_helper_source_changed')
    spec=importlib.util.spec_from_file_location('cycle4_exact_maintained_assessment',path)
    helper=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=helper
    spec.loader.exec_module(helper)
""",
            f"""    need(len(body)<=4*1024**2
         and hashlib.sha256(body).hexdigest()==manifest.get(name)=={ASSESSMENT_HELPER_SHA256!r},
         'assessment_helper_source_changed')
    spec=importlib.util.spec_from_file_location('cycle6_exact_maintained_assessment',path)
    helper=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=helper
    exec(compile(body,str(path),'exec',dont_inherit=True),helper.__dict__)
""",
        ),
    )
    for old, new in replacements:
        if text.count(old) != 1:
            raise RuntimeError('exact_cycle5_assessment_source_required')
        text = text.replace(old, new, 1)
    compile(text, 'npm-recovery.py', 'exec', dont_inherit=True)
    return text
