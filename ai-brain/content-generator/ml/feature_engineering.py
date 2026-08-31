def extract_features(log):
    log = log.lower()

    return [
        len(log),                      # length of log
        1 if "admin" in log else 0,    # admin keyword
        1 if "config" in log else 0,   # config keyword
        1 if "scp" in log else 0,      # data exfiltration
        1 if "sudo" in log else 0      # privilege escalation
    ]