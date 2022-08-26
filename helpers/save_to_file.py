import json
import pathlib
from typing import Dict, Union, List

__version__ = "1.4"


async def _prepare_to_json(data) -> str:
    return json.dumps(data)


async def _prepare_to_txt(data) -> str:
    return str(data)


async def save_data_to_file(data: Union[Dict, List, str], full_path: pathlib.Path):
    """Save data to file
    Output format based on file extension in full_path
    """
    path_to_dir = full_path.parent  # type: pathlib.Path
    path_to_dir.mkdir(parents=True, exist_ok=True)

    extension_dict = {
        'json': _prepare_to_json,
        'txt': _prepare_to_txt,
    }

    name = full_path.name
    split = name.rsplit('.', maxsplit=1)
    len_split = len(split)

    if len_split == 2:
        file_extension = split[1]
        try:
            prepare_to_format = extension_dict[file_extension]
        except KeyError:
            pass
        else:
            data = await prepare_to_format(data)

    with open(str(full_path), mode='w') as file:
        file.write(data)

    return full_path
