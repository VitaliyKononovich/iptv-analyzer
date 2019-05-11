import datetime
from ts.ts_reader import TSReader
from views.viever import Viewer
from ts.ts_stat import Statistics


source_file = r'c:\Users\vitaliy_ko\PycharmProjects\iptv\samples\setanta2.m2ts'
source_file = r'd:\Downloads\692-inadv-vid-1k-387623377.ts'

def main():
    psize = 188
    chunksize = 7
    viewer = Viewer()
    stats = Statistics()
    ts_reader = TSReader(statistics=stats)

    with open(source_file, 'rb') as file:
        while True:
            data = file.read(psize * chunksize)
            if not data:
                break
            dt = datetime.datetime.now()
            ts_reader.read(data, dt=dt)

    stats_sorted = sorted(stats.get_stat(), key=lambda k: k['pid'])
    viewer.print_stat(stats_sorted, ts_reader.get_programs_data(), ts_reader.known_pids)


if __name__ == '__main__':
    main()
