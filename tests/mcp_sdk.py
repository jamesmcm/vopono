"""Optional interoperability check: install the official Python `mcp` SDK first."""
import asyncio
import os
import sys
import tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    with tempfile.TemporaryDirectory(prefix='vopono-sdk-') as config:
        server = StdioServerParameters(command=sys.argv[1], args=['mcp', 'serve'],
            env={**os.environ, 'XDG_CONFIG_HOME': config})
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                # Pydantic wire aliases are stable across SDK API naming changes.
                initialized = (await session.initialize()).model_dump(by_alias=True)
                assert initialized['serverInfo']['name'] == 'vopono'
                tools = await session.list_tools()
                assert len(tools.tools) == 8
                profiles = (await session.call_tool('profiles_list', {})).model_dump(by_alias=True)
                assert profiles['structuredContent']['profiles'] == []
                missing = (await session.call_tool('job_status', {'job_id': 'missing'})).model_dump(by_alias=True)
                assert missing['isError']
                await session.send_ping()
    print('PASS: official MCP SDK handshake, discovery, schemas, structured results, errors, ping and shutdown')


asyncio.run(main())
