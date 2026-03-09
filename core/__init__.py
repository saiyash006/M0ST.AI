import os


def load_env(path: str = ".env") -> None:
    """
    Minimal .env loader to avoid external deps.
    Existing environment variables take precedence.
    Searches in cwd first, then project root.
    """
    candidates = [path]
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(project_root, path))

    target = None
    for p in candidates:
        if os.path.exists(p):
            target = p
            break
    if target is None:
        return

    try:
        with open(target, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("'").strip('"')
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        return
