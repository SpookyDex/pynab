import config

INTERFACES = []

for ifaces in config.postprocess.get('process_movies'):
    from pynab.interfaces.movie import ifaces
    INTERFACES.append(ifaces)