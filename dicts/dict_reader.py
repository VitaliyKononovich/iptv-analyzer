import csv


def load_dictionary_csv(file: str) -> list:

    dictionary = list()
    with open(file, newline='') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=',')
        dictionary = [{k: v for k, v in row.items()} for row in reader]

    for item in dictionary:
        item['value1'] = int(item['value1'])
        item['value2'] = int(item['value2'])
        if item['range'] == 'True':
            item['range'] = True
        else:
            item['range'] = False
    return dictionary


def find(dictionary: list, value: int) -> str:
    for item in dictionary:
        if item['range']:
            if value in range(item['value1'], item['value2']+1):
                return item['description']
        else:
            if value == item['value1']:
                return item['description']
    return None
