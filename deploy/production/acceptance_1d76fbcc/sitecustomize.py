"""Install source-bound lifetime guards into first-party Python descendants."""
import os

if os.environ.get('DEVRES_ACCEPTANCE_SUBPROCESS_GUARD') == '1':
    try:
        import acceptance_common
        acceptance_common.install_subprocess_guard()
    except BaseException:
        os._exit(125)
