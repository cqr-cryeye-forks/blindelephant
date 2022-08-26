import argparse
import asyncio
import os
import pathlib
import re
from typing import Dict, Union, List
from helpers._utils import print_log
from helpers.save_to_file import save_data_to_file


async def cli():
    """Command Line Interface
    """
    parser = argparse.ArgumentParser(description='Scan ip for open ports')
    parser.add_argument('url',
                        type=str,
                        help='url for scan')

    parser.add_argument('--web-app',
                        type=str,
                        metavar='APP',
                        dest="web_app",
                        help='Name of web app. For example wordpress',
                        required=False,
                        default=None)

    parser.add_argument('--result',
                        type=pathlib.Path,
                        metavar='PATH',
                        dest="result_path",
                        help='Path to saving result')

    parser.add_argument('-v', '--venv',
                        action='store_true',
                        default=False,
                        help='run as venv')

    return parser.parse_args()


async def _parse_supported_items(data: List[str]) -> Dict[str, List[str]]:
    pattern__configured = 'Currently configured web apps:'
    pattern__web_app = re.compile(r'(?P<web_app>\w+)\swith\s\d+\splugins.*')
    pattern__plugin = re.compile(r'\s-\s(?P<plugin>[\w-]+)')
    flag__configured = False
    app_dict = {}
    for line in data:
        if not flag__configured and line.startswith(pattern__configured):
            flag__configured = True
            continue
        web_app = None
        if is_web_app := re.match(pattern__web_app, line):
            web_app = is_web_app['web_app']
            app_dict[web_app] = []
            continue
        if is_plugin := re.match(pattern__plugin, line):
            plugin = is_plugin['plugin']
            app_dict[web_app].append(plugin)
            continue
    return app_dict


async def _scan_base(tool_command: str, no_join: bool = False) -> Union[str, List[str]]:
    await print_log(f'tool_command_main_scan: {tool_command}')
    tool = await asyncio.create_subprocess_shell(tool_command,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    output = []
    await tool.wait()
    async for line in tool.stdout:
        data = line.decode()
        output.append(data)
    return output if no_join else ''.join(output)


async def get_supported_items_list(tool_base_command: str) -> Dict[str, List[str]]:
    tool_command_list = ' '.join([
        tool_base_command,
        '--list',
    ])
    output = await _scan_base(tool_command_list, no_join=True)

    await print_log(str(output))

    result = await _parse_supported_items(data=output)
    await print_log(str(result))
    return result


async def scan_web_app(tool_base_command: str, target_url: str, web_app: str) -> str:
    tool_command_main_scan = ' '.join([tool_base_command, target_url, web_app])
    return await _scan_base(tool_command=tool_command_main_scan)


async def scan_plugin(tool_base_command: str, target_url: str, web_app: str, plugin: str) -> str:
    tool_command_plugin_scan = ' '.join([tool_base_command, '--skip', '--pluginName', plugin, target_url, web_app])
    return await _scan_base(tool_command=tool_command_plugin_scan)


async def _web_app_processing(tool_base_command: str, target_url: str, web_app: str, app_dict: Dict) -> Dict:
    web_app_data = await scan_web_app(tool_base_command=tool_base_command, target_url=target_url, web_app=web_app)
    result = {
        'name': web_app,
        'data': web_app_data,
        'plugins': []
    }

    for plugin in app_dict[web_app]:
        plugin_data = await scan_plugin(tool_base_command=tool_base_command, target_url=target_url, web_app=web_app,
                                        plugin=plugin)
        result['plugins'].append(
            {
                'name': plugin,
                'data': plugin_data,
            }
        )
    return result


async def main():
    # [init_params]-[BEGIN]
    parsed_args = await cli()

    APP_DIR = os.environ['APP_DIR'] or pathlib.Path(__file__).parent
    python_for_app_path = APP_DIR.joinpath("venv", "bin", "python") if parsed_args.venv else 'python'
    tool_path = APP_DIR.joinpath("blindelephant", "BlindElephant.py")

    target_url = parsed_args.url
    web_app = parsed_args.web_app

    tool_base_command = ' '.join([
        str(python_for_app_path),
        str(tool_path),
    ])

    # local_path = pathlib.Path().absolute()
    # [init_params]-[END]

    app_dict = await get_supported_items_list(tool_base_command=tool_base_command)

    result = []
    if not web_app:
        for web_app in app_dict.keys():
            app_data = await _web_app_processing(tool_base_command=tool_base_command, target_url=target_url,
                                                 web_app=web_app,
                                                 app_dict=app_dict)
            result.append(app_data)
    else:
        app_data = await _web_app_processing(tool_base_command=tool_base_command, target_url=target_url,
                                             web_app=web_app,
                                             app_dict=app_dict)
        result.append(app_data)

    import pprint
    pprint.PrettyPrinter(indent=4).pprint(result)

    # [save_result]-[BEGIN]
    result_path = parsed_args.result_path
    await save_data_to_file(data=result, full_path=result_path)
    await print_log(f'Result saved at:{result_path}')
    # [save_result]-[END]
    return


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
