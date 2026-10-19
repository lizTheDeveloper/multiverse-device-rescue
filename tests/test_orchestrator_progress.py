from rescue.orchestrator import Orchestrator
from rescue.models import CheckResult
from unittest.mock import patch


def test_run_checks_calls_on_progress_around_every_module():
    mod = type('M', (), {'name': 'a', 'check': lambda self, p: CheckResult(module_name='a')})()
    seen = []
    with patch('rescue.orchestrator.discover_modules', return_value=[mod]), \
         patch('rescue.orchestrator.filter_by_platform', side_effect=lambda m, p: m), \
         patch('rescue.orchestrator.topological_sort', side_effect=lambda m: m), \
         patch('rescue.orchestrator.gather_profile'):
        Orchestrator(modules_dir='x').run_checks(
            on_progress=lambda phase, i, n, m, c: seen.append((phase, i, n, m.name)))
    assert seen == [('start', 1, 1, 'a'), ('done', 1, 1, 'a')]


def test_run_checks_names_every_module_before_the_first_starts():
    order = []
    a = type('M', (), {'name': 'a', 'check': lambda self, p: order.append('check a') or CheckResult(module_name='a')})()
    b = type('M', (), {'name': 'b', 'check': lambda self, p: order.append('check b') or CheckResult(module_name='b')})()
    with patch('rescue.orchestrator.discover_modules', return_value=[a, b]), \
         patch('rescue.orchestrator.filter_by_platform', side_effect=lambda m, p: m), \
         patch('rescue.orchestrator.topological_sort', side_effect=lambda m: m), \
         patch('rescue.orchestrator.gather_profile'):
        Orchestrator(modules_dir='x').run_checks(on_plan=lambda mods: order.append([m.name for m in mods]))
    assert order == [['a', 'b'], 'check a', 'check b']
