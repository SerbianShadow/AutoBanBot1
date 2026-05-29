import discord
import asyncio
import os
from discord.ext import commands

# Local imports
import config
from core import database


intents = discord.Intents.default()
intents.message_content = True  # Needed to scan messages for spam and phishing links
intents.members = True          # Needed to detect suspicious accounts joining the server


bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')
    
    # Make sure all our database tables are created before the bot starts working
    database.init_db()
    print("Database initialized successfully.")

async def load_extensions():
    for filename in os.listdir('./cogs'):
        if filename.endswith('.py'):
            await bot.load_extension(f'cogs.{filename[:-3]}')
            print(f"Loaded extension: {filename}")

async def main():
    async with bot:
        await load_extensions()
        
        await bot.start(config.BOT_TOKEN)

if __name__ == '__main__':
    asyncio.run(main())