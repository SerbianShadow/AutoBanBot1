import discord
import asyncio
import os
from discord.ext import commands

# Local imports
import config
from core import database

# These are required for the bot to see what people type and when they join.
intents = discord.Intents.default()
intents.message_content = True  # Needed to scan messages for spam and phishing links
intents.members = True          # Needed to detect suspicious accounts joining the server

# Create the bot instance. It listens for commands starting with '!'
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    """This function triggers automatically when the bot successfully connects to Discord."""
    print(f'Logged in as {bot.user.name}')
    
    # Make sure all our database tables are created before the bot starts working
    database.init_db()
    print("Database initialized successfully.")

async def load_extensions():
    for filename in os.listdir('./cogs'):
        if filename.endswith('.py'):
            # We load the file, but we have to strip off the '.py' at the end of the filename
            await bot.load_extension(f'cogs.{filename[:-3]}')
            print(f"Loaded extension: {filename}")

async def main():
    async with bot:
        # 1. Load our moderation tools and modules
        await load_extensions()
        
        # 2. Connect to Discord using the secret token from our config
        await bot.start(config.BOT_TOKEN)

if __name__ == '__main__':
    asyncio.run(main())