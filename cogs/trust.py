import discord
from discord.ext import commands
from core import utils, database

class Trust(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command(name="trust")
    async def check_trust(self, ctx, member: discord.Member = None):
        if not member:
            member = ctx.author
            
        user_data = database.get_user_data(member.id, ctx.guild.id)
        
        if not user_data:
            await ctx.send(f"{member.display_name} has no trust data yet.")
            return

        score = utils.calculate_trust_score(user_data, member)
        
        embed = discord.Embed(title=f"Trust Factor: {member.display_name}", color=discord.Color.green())
        embed.add_field(name="Score", value=f"{score}/100", inline=False)
        embed.add_field(name="Messages Analyzed", value=str(user_data[2]), inline=True)
        # Handle string/datetime formatting
        first_seen = user_data[4]
        if isinstance(first_seen, str):
             # Parse default sqlite timestamp
             first_seen = first_seen.split('.')[0] 
        else:
             first_seen = first_seen.strftime("%Y-%m-%d %H:%M:%S")

        embed.add_field(name="First Seen", value=str(first_seen), inline=True)
        
        await ctx.send(embed=embed)

async def setup(bot):
    await bot.add_cog(Trust(bot))
