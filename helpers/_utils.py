import datetime

DELIMITER = '[:::]'


async def print_log(message):
    print(f'{DELIMITER}[{datetime.datetime.now(datetime.timezone.utc)}]:{message}')
