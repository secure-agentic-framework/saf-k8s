"""Read-only CPU and memory limit probe for this process's own cgroup."""
from decimal import Decimal
from fractions import Fraction
import json
from pathlib import Path


def mounts():
    result = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        before, after = left.split(), right.split()
        result.append({'filesystem': after[0], 'root': Path(before[3]),
                       'mountpoint': Path(before[4].replace('\\040', ' ')),
                       'options': set(after[2].split(','))})
    return result


def cgroups():
    rows = {}
    for line in Path('/proc/self/cgroup').read_text().splitlines():
        _hierarchy, controllers, path = line.split(':', 2)
        rows[controllers] = Path(path)
    return rows


def mounted_path(cgroup_path, mount):
    root = mount['root']
    path_text, root_text = str(cgroup_path), str(root)
    if path_text == root_text:
        relative = ''
    elif root_text == '/' or path_text.startswith(root_text.rstrip('/') + '/'):
        relative = path_text[len(root_text):].lstrip('/')
    else:
        return None
    return mount['mountpoint'] / relative


def hierarchy(leaf, root):
    current = leaf
    while True:
        yield current
        if current == root or current.parent == current:
            break
        current = current.parent


def read_v2(mount, path):
    leaf = mounted_path(path, mount)
    if leaf is None:
        return None
    dirs = list(hierarchy(leaf, mount['mountpoint']))
    cpu = []
    memory = []
    for directory in dirs:
        cpu_file = directory / 'cpu.max'
        if cpu_file.is_file():
            quota, period = cpu_file.read_text().split()
            if quota != 'max':
                cpu.append({'path': str(cpu_file), 'millicores': Fraction(int(quota) * 1000, int(period))})
        mem_file = directory / 'memory.max'
        if mem_file.is_file():
            value = mem_file.read_text().strip()
            if value != 'max':
                memory.append({'path': str(mem_file), 'bytes': int(value)})
    return {'version': 2, 'leaf': str(leaf), 'cpu': cpu, 'memory': memory}


def read_v1(controller, mount, path):
    leaf = mounted_path(path, mount)
    if leaf is None:
        return None
    dirs = list(hierarchy(leaf, mount['mountpoint']))
    cpu, memory = [], []
    for directory in dirs:
        if controller == 'cpu':
            quota_file, period_file = directory / 'cpu.cfs_quota_us', directory / 'cpu.cfs_period_us'
            if quota_file.is_file() and period_file.is_file():
                quota, period = int(quota_file.read_text()), int(period_file.read_text())
                if quota > 0 and period > 0:
                    cpu.append({'path': str(quota_file), 'millicores': Fraction(quota * 1000, period)})
        else:
            limit_file = directory / 'memory.limit_in_bytes'
            if limit_file.is_file():
                value = int(limit_file.read_text())
                if value < (1 << 60):
                    memory.append({'path': str(limit_file), 'bytes': value})
    return {'version': 1, 'leaf': str(leaf), 'cpu': cpu, 'memory': memory}


def fmt(value):
    decimal = Decimal(value.numerator) / Decimal(value.denominator)
    return format(decimal.normalize(), 'f')


def main():
    rows = cgroups()
    available_mounts = mounts()
    v2_path = rows.get('')
    result = None
    if v2_path is not None:
        mount = next((item for item in available_mounts if item['filesystem'] == 'cgroup2'), None)
        if mount is not None:
            result = read_v2(mount, v2_path)
    if result is None:
        cpu_path = next((path for controllers, path in rows.items()
                         if 'cpu' in controllers.split(',')), None)
        memory_path = next((path for controllers, path in rows.items()
                            if 'memory' in controllers.split(',')), None)
        cpu_mount = next((item for item in available_mounts if item['filesystem'] == 'cgroup'
                          and 'cpu' in item['options']), None)
        memory_mount = next((item for item in available_mounts if item['filesystem'] == 'cgroup'
                             and 'memory' in item['options']), None)
        if cpu_path is not None and memory_path is not None and cpu_mount and memory_mount:
            cpu_data = read_v1('cpu', cpu_mount, cpu_path)
            mem_data = read_v1('memory', memory_mount, memory_path)
            result = {'version': 1, 'cpu': cpu_data['cpu'], 'memory': mem_data['memory'],
                      'leaf': {'cpu': cpu_data['leaf'], 'memory': mem_data['leaf']}}
    if result is None:
        print(json.dumps({'supported': False, 'reason': 'own-cgroup-cpu-memory-files-unavailable'}))
        raise SystemExit(2)
    if not result['cpu'] or not result['memory']:
        print(json.dumps({'supported': False, 'reason': 'finite-cpu-or-memory-bound-not-visible',
                          'observed': {key: len(result[key]) for key in ('cpu', 'memory')}}))
        raise SystemExit(2)
    cpu_bound = min(result['cpu'], key=lambda item: item['millicores'])
    memory_bound = min(result['memory'], key=lambda item: item['bytes'])
    print(json.dumps({'supported': True, 'cgroup_version': result['version'],
        'cgroup_leaf': result['leaf'],
        'cpu_effective_limit_millicores': fmt(cpu_bound['millicores']),
        'cpu_limiting_counter': cpu_bound['path'],
        'cpu_hierarchy_limits': [{'path': item['path'], 'millicores': fmt(item['millicores'])}
                                 for item in result['cpu']],
        'memory_effective_limit_bytes': memory_bound['bytes'],
        'memory_limiting_counter': memory_bound['path'],
        'memory_hierarchy_limits': result['memory']}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
