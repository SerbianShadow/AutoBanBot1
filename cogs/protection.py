import discord
from discord.ext import commands
import datetime
import time
import re
from core import utils, database
import config

class Protection(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.message_history = {}  # user_id -> list of (timestamp, message_object)

    async def log_to_channel(self, guild, embed):
        log_channel_id = getattr(config, "LOG_CHANNEL_ID", None)
        if not log_channel_id:
            return
            
        try:
            log_channel_id = int(log_channel_id)
        except (ValueError, TypeError):
            print("Invalid LOG_CHANNEL_ID format in config.py")
            return
            
        channel = guild.get_channel(log_channel_id) or self.bot.get_channel(log_channel_id)
        if not channel:
            try:
                channel = await self.bot.fetch_channel(log_channel_id)
            except Exception as e:
                print(f"Failed to fetch log channel with ID {log_channel_id}: {e}")
                return

        if channel:
            try:
                await channel.send(embed=embed)
            except discord.Forbidden:
                # Fallback in case the bot lacks the 'Embed Links' permission
                try:
                    text_fallback = f"**Moderation Action**\n**User:** {embed.author.name}\n"
                    for field in embed.fields:
                        text_fallback += f"**{field.name}:** {field.value}\n"
                    await channel.send(content=text_fallback)
                except Exception as e:
                    print(f"Failed to send fallback text log: {e}")
            except Exception as e:
                print(f"Failed to send log message: {e}")

    async def execute_punishment(self, member: discord.Member, reason: str, severity: str = "SPAM"):
        guild = member.guild
        embed = discord.Embed(title="Moderation Action", color=discord.Color.red(), timestamp=datetime.datetime.now(datetime.timezone.utc))
        embed.set_author(name=f"{member} ({member.id})", icon_url=member.display_avatar.url if getattr(member, "display_avatar", None) else None)
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(name="Severity", value=severity, inline=True)

        if getattr(member.guild_permissions, "administrator", False):
            print(f"[Log] Skipping punishment for Administrator {member}")
            embed.add_field(name="Action", value="Skipped Punishment (User is Administrator)", inline=False)
            await self.log_to_channel(guild, embed)
            return

        # High severity or suspected bot account doing malice -> Automatic Ban
        if getattr(member, 'bot', False) or severity == "HIGH":
            try:
                msg = f"You have been banned from {guild.name} for: {reason}\n"
                appeal_link = getattr(config, 'SUPPORT_SERVER_LINK', None)
                if appeal_link:
                    msg += f"If you believe this was an error, you can appeal here: {appeal_link}"
                await member.send(msg)
            except (discord.Forbidden, discord.HTTPException):
                pass
            
            try:
                await member.ban(reason=reason)
                embed.add_field(name="Action", value="Banned", inline=False)
            except discord.Forbidden:
                embed.add_field(name="Action", value="Failed to Ban (Missing Permissions)", inline=False)
            await self.log_to_channel(guild, embed)
            return

        # Moderate severity SPAM -> Tiered Timeouts leading to Ban
        strikes = database.add_user_strike(member.id, guild.id)
        embed.add_field(name="Strikes", value=str(strikes), inline=True)

        if strikes == 1:
            try:
                duration_secs = getattr(config, "TIMEOUT_DURATION_1ST", 600)
                until = discord.utils.utcnow() + datetime.timedelta(seconds=duration_secs)
                
                try:
                    msg = f"You have been muted in {guild.name} for {duration_secs // 60} minutes for: {reason}\n"
                    appeal_link = getattr(config, 'SUPPORT_SERVER_LINK', None)
                    if appeal_link:
                        msg += f"If you believe this was an error, you can appeal here: {appeal_link}"
                    await member.send(msg)
                except (discord.Forbidden, discord.HTTPException):
                    pass
                
                await member.timeout(until, reason=reason)
                embed.add_field(name="Action", value=f"Timeout ({duration_secs // 60} minutes)", inline=False)
            except discord.Forbidden:
                embed.add_field(name="Action", value="Failed to Timeout (Missing Permissions)", inline=False)
            except Exception as e:
                embed.add_field(name="Action", value=f"Error: {e}", inline=False)

        elif strikes == 2:
            try:
                duration_secs = getattr(config, "TIMEOUT_DURATION_2ND", 3600)
                until = discord.utils.utcnow() + datetime.timedelta(seconds=duration_secs)
                
                try:
                    msg = f"You have been muted in {guild.name} for {duration_secs // 60} minutes for: {reason}\n"
                    appeal_link = getattr(config, 'SUPPORT_SERVER_LINK', None)
                    if appeal_link:
                        msg += f"If you believe this was an error, you can appeal here: {appeal_link}"
                    await member.send(msg)
                except (discord.Forbidden, discord.HTTPException):
                    pass
                
                await member.timeout(until, reason=reason)
                embed.add_field(name="Action", value=f"Timeout ({duration_secs // 60} minutes)", inline=False)
            except discord.Forbidden:
                embed.add_field(name="Action", value="Failed to Timeout (Missing Permissions)", inline=False)
            except Exception as e:
                embed.add_field(name="Action", value=f"Error: {e}", inline=False)
                
        else: # strikes >= 3
            try:
                duration_secs = getattr(config, "TIMEOUT_DURATION_3RD", 86400)
                until = discord.utils.utcnow() + datetime.timedelta(seconds=duration_secs)
                
                try:
                    msg = f"You have been muted in {guild.name} for {duration_secs // 3600} hours for: {reason}\n"
                    appeal_link = getattr(config, 'SUPPORT_SERVER_LINK', None)
                    if appeal_link:
                        msg += f"If you believe this was an error, you can appeal here: {appeal_link}"
                    await member.send(msg)
                except (discord.Forbidden, discord.HTTPException):
                    pass
                
                await member.timeout(until, reason=reason)
                embed.add_field(name="Action", value=f"Timeout ({duration_secs // 3600} hours)", inline=False)
            except discord.Forbidden:
                embed.add_field(name="Action", value="Failed to Timeout (Missing Permissions)", inline=False)
            except Exception as e:
                embed.add_field(name="Action", value=f"Error: {e}", inline=False)

        await self.log_to_channel(guild, embed)

        

    async def _scan_for_threats(self, message, is_edit=False):
        user_id = message.author.id
        guild_id = message.guild.id
        
        qr_urls = []
        if getattr(config, "ENABLE_QR_SCANNING", False) and message.attachments:
            for attachment in message.attachments:
                # Check for common image formats
                if any(attachment.filename.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.webp']):
                    try:
                        image_bytes = await attachment.read()
                        extracted = utils.extract_urls_from_image(image_bytes)
                        qr_urls.extend(extracted)
                    except Exception as e:
                        print(f"[Log] Failed to read attachment {attachment.filename}: {e}")

        # Combine found URLs for comprehensive scanning
        url_pattern = r'\b(?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        found_urls = re.findall(url_pattern, message.content)
        if qr_urls:
            found_urls.extend(qr_urls)
            # Create a virtual content string for functions that expect raw text
            scan_content = message.content + " " + " ".join(qr_urls)
        else:
            scan_content = message.content
        
        safe_browsing_flagged = False
        flagged_url = None
        
        if getattr(config, "ENABLE_SAFE_BROWSING", True) and found_urls:
            for url in found_urls:
                if await utils.check_safe_browsing(url):
                    safe_browsing_flagged = True
                    flagged_url = url
                    break
                    
        if safe_browsing_flagged:
            severity = "HIGH"
            action_type = "SAFE_BROWSING_DETECTED"
            if is_edit:
                action_type = "BAIT_AND_SWITCH_DETECTED"
                
            database.store_spam_message(
                user_id, guild_id, message.channel.id,
                message.content, "SAFE_BROWSING_MALWARE"
            )
            try:
                await message.delete()
            except discord.NotFound:
                pass
                
            warn_text = f"{message.author.mention}, malicious link detected by Google Safe Browsing and removed!"
            if is_edit:
                warn_text = f" **BAIT AND SWITCH DETECTED!** {message.author.mention} tried to inject a malicious link into an old message!"
            await message.channel.send(warn_text, delete_after=5)
            database.log_action(user_id, guild_id, action_type, f"Posted known malicious URL: {flagged_url}")
            await self.execute_punishment(message.author, f"Posted known malicious URL: {flagged_url}", severity)
            return True

        # Phishing Detection
        if getattr(config, "ENABLE_PHISHING_DETECTION", True):
            is_phishing, url = await utils.check_phishing(scan_content)
            if is_phishing:
                detection_type = "PHISHING"
                severity = "HIGH"
                action_type = "PHISHING_DETECTED"
                warn_text = f"{message.author.mention}, suspicious link detected and removed!"
                
                if is_edit:
                    action_type = "BAIT_AND_SWITCH_DETECTED"
                    warn_text = f" **BAIT AND SWITCH DETECTED!** {message.author.mention} tried to inject a phishing link into an old message!"
                elif url in qr_urls:
                    detection_type = "QR_PHISHING"
                    warn_text = f"📸 **QR Code Scam Blocked!** {message.author.mention}, nice try hiding a malicious link inside an image! Our optical scanners found it and removed it."


                database.store_spam_message(
                    user_id, guild_id, message.channel.id,
                    message.content, detection_type
                )
                try:
                    await message.delete()
                except discord.NotFound:
                    pass
                await message.channel.send(warn_text, delete_after=5)
                database.log_action(user_id, guild_id, action_type, f"Posted suspicious URL: {url}")
                await self.execute_punishment(message.author, f"Posted phishing link: {url}", severity)
                return True

        # Algorithmic Domain Entropy
        is_dga, dga_domain = await utils.check_domain_entropy(scan_content)
        if is_dga:
            severity = "HIGH"
            action_type = "DGA_DETECTED"
            warn_text = f"{message.author.mention}, that link looks like a randomly generated scam domain and was removed!"
            
            if is_edit:
                action_type = "BAIT_AND_SWITCH_DETECTED"
                warn_text = f"**BAIT AND SWITCH DETECTED!** {message.author.mention} tried to inject a scam domain into an old message!"

            database.store_spam_message(
                user_id, guild_id, message.channel.id,
                message.content, "HIGH_ENTROPY_DGA"
            )
            try:
                await message.delete()
            except discord.NotFound:
                pass
            await message.channel.send(warn_text, delete_after=5)
            database.log_action(user_id, guild_id, action_type, f"Posted highly randomized domain: {dga_domain}")
            await self.execute_punishment(message.author, f"Posted randomly generated scam domain: {dga_domain}", severity)
            return True

        # Domain Age Detection (API Ninjas)
        if getattr(config, "ENABLE_DOMAIN_AGE_DETECTION", True):
            is_new_domain, domain, age_days = await utils.check_domain_age(scan_content)
            if is_new_domain:
                # Check if user is trusted
                trust_score = self._get_trust_score(user_id, guild_id, message.author)
                exempt_score = getattr(config, "NEW_DOMAIN_TRUST_EXEMPT_SCORE", 50)
                
                if trust_score >= exempt_score and not is_edit:
                    print(f"[Log] User {message.author} is trusted (score={trust_score}). Ignoring infant domain: {domain}")
                    database.log_action(
                        user_id, guild_id, "NEW_DOMAIN_TRUST_BYPASS",
                        f"Trusted user posted new domain: {domain} (age={age_days}d)"
                    )
                    return False # Skip punishment
                
                database.store_spam_message(
                    user_id, guild_id, message.channel.id,
                    message.content, "NEW_DOMAIN"
                )
                
                try:
                    await message.delete()
                except discord.NotFound:
                    pass

                action_type = "NEW_DOMAIN_DETECTED"
                if age_days < 0:
                    warning_text = f"**Link Removed!** {message.author.mention}, your link (`{domain}`) was deleted because it is untrackable and often used by scammers."
                else:
                    warning_text = f"**Warning!** {message.author.mention}'s message was deleted for containing a brand new domain (`{domain}`). It was registered only {age_days} days ago."

                if is_edit:
                    action_type = "BAIT_AND_SWITCH_DETECTED"
                    warning_text = f"**BAIT AND SWITCH DETECTED!** {message.author.mention} tried to inject a suspicious new domain (`{domain}`) into an old message!"

                await message.channel.send(warning_text, delete_after=15)

                database.log_action(user_id, guild_id, action_type, f"Posted infant or untrackable domain ({age_days}): {domain}")
                # Treat untrackable domains (-1, -2) as HIGH severity
                severity = "HIGH" if (age_days < 0 or is_edit) else "HIGH" 
                await self.execute_punishment(message.author, f"Posted newly registered or untrackable domain: {domain}", severity)
                return True

        return False

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author.bot or not message.guild:
            return

        current_time = time.time()
        user_id = message.author.id
        guild_id = message.guild.id

        # Initialize per-user caches
        if user_id not in self.message_history:
            self.message_history[user_id] = []

        # Expire messages older than 60 seconds from rate-limit cache and remove deleted messages
        self.message_history[user_id] = [
            (t, m) for (t, m) in self.message_history[user_id]
            if current_time - t < 60 and m is not None
        ]

        # Rate Limiting
        if len(self.message_history[user_id]) >= getattr(config, "MAX_MESSAGES_PER_MINUTE", 10):
            # Delete all recent messages to clean up the spam.
            messages_to_delete = [message]
            for i, (t, msg) in enumerate(self.message_history[user_id]):
                if msg is not None:
                    messages_to_delete.append(msg)
                    self.message_history[user_id][i] = (t, None) # mark as deleted to prevent double counting

            # Prepare for DB and bulk deletion
            msgs_by_channel = {}
            for msg in messages_to_delete:
                database.store_spam_message(
                    user_id, guild_id, msg.channel.id,
                    msg.content, "RATE_LIMIT_BURST"
                )
                msgs_by_channel.setdefault(msg.channel.id, []).append(msg)

            for channel_id, msgs in msgs_by_channel.items():
                channel = getattr(msgs[0], 'channel', None)
                if not channel:
                    continue
                try:
                    if len(msgs) > 1:
                        await channel.delete_messages(msgs)
                    else:
                        await msgs[0].delete()
                except discord.NotFound:
                    pass
                except Exception as e:
                    print(f"Failed to delete rate-limit spam messages: {e}")

            await message.channel.send(
                f"{message.author.mention}, you are sending messages too fast!",
                delete_after=5
            )
            database.log_action(
                user_id, guild_id, "RATE_LIMIT_EXCEEDED",
                f"Exceeded message rate limit. Purged {len(messages_to_delete)} messages."
            )
            await self.execute_punishment(message.author, "Exceeded message rate limit", "SPAM")

            # Reset caches so they don't get double punished when they speak again
            self.message_history[user_id] = []
            return

        # Add current message to rate-limit history
        self.message_history[user_id].append((current_time, message))

        spam_repeat_window = getattr(config, "SPAM_REPEAT_WINDOW", 5)
        
        # Pull the last N valid active messages within the last 60 seconds directly from history
        recent_active = [m for t, m in self.message_history[user_id] if m is not None]
        window_messages = recent_active[-spam_repeat_window:]

        is_spam, spam_indices = utils.detect_repeated_spam(
            [m.content for m in window_messages]
        )

        if is_spam:
            trust_score = self._get_trust_score(user_id, guild_id, message.author)
            spam_exempt_score = getattr(config, "SPAM_TRUST_EXEMPT_SCORE", 70)

            if trust_score >= spam_exempt_score:
                # Trusted users: warn only, do not delete
                await message.channel.send(
                    f"{message.author.mention}, you are repeating yourself — please avoid spam.",
                    delete_after=5
                )
                database.log_action(
                    user_id, guild_id, "SPAM_WARNING",
                    f"Repeated text detected (trust={trust_score}, exempt from deletion)"
                )
            else:
                messages_to_delete = []
                for idx in spam_indices:
                    msg = window_messages[idx]
                    messages_to_delete.append(msg)
                    database.store_spam_message(
                        user_id, guild_id, msg.channel.id,
                        msg.content, "REPEATED_TEXT"
                    )
                    
                    # Mark as None in message_history to avoid rate-limit double-triggering
                    for i, (t, h_msg) in enumerate(self.message_history[user_id]):
                        if h_msg == msg:
                            self.message_history[user_id][i] = (t, None)

                # Group by channel for bulk deletion
                msgs_by_channel = {}
                for msg in messages_to_delete:
                    msgs_by_channel.setdefault(msg.channel.id, []).append(msg)

                for channel_id, msgs in msgs_by_channel.items():
                    channel = getattr(msgs[0], 'channel', None)
                    if not channel:
                        continue
                    try:
                        if len(msgs) > 1:
                            await channel.delete_messages(msgs)
                        else:
                            await msgs[0].delete()
                    except discord.NotFound:
                        pass
                    except Exception as e:
                        print(f"Failed to delete repeated text spam messages: {e}")

                await message.channel.send(
                    f"{message.author.mention}, please stop spamming!",
                    delete_after=5
                )
                database.log_action(
                    user_id, guild_id, "SPAM_DETECTED",
                    f"Repeated message content. Deleted {len(messages_to_delete)} messages."
                )
                await self.execute_punishment(message.author, "Repeated text spam", "SPAM")

            return

        # Run Threat Scans
        if await self._scan_for_threats(message, is_edit=False):
            return

        # Update user stats for Trust Factor
        database.update_user_stats(user_id, guild_id)

    @commands.Cog.listener()
    async def on_message_edit(self, before, after):
        if after.author.bot or not after.guild:
            return
            
        # Ignore if the content didn't change
        if before.content == after.content:
            return

        # Run Threat Scans on the edited content
        if await self._scan_for_threats(after, is_edit=True):
            print(f"[Log] Caught Bait-and-Switch by {after.author}! Original: '{before.content}', Edited: '{after.content}'")

    @commands.Cog.listener()
    async def on_member_join(self, member):
        # Scam Account Detection (Account Age)
        account_age = datetime.datetime.now(datetime.timezone.utc) - member.created_at
        if account_age.total_seconds() < (config.NEW_ACCOUNT_AGE_THRESHOLD_HOURS * 3600):
            database.log_action(
                member.id, member.guild.id, "SUSPICIOUS_ACCOUNT",
                f"Account created {account_age} ago"
            )
            print(f"Suspicious account joined: {member.name} (Age: {account_age})")

        # Raid Detection: Join Velocity
        if not hasattr(self, 'join_history'):
            self.join_history = []
        
        current_time = time.time()
        # Keep only joins from the last 60 seconds
        self.join_history = [t for t in self.join_history if current_time - t < 60]
        self.join_history.append(current_time)
        
        # Threshold: 5 joins per minute is suspicious for small servers
        raid_threshold = getattr(config, "RAID_VELOCITY_THRESHOLD", 5)
        if len(self.join_history) >= raid_threshold:
            print(f"[Log] High join velocity detected! ({len(self.join_history)} joins in 60s)")
            database.log_action(
                0, member.guild.id, "RAID_VELOCITY_DETECTED",
                f"Detected {len(self.join_history)} joins in 60 seconds. Possible RAID."
            )
            
            # Alert moderators or set channel slowmode
            log_embed = discord.Embed(
                title="RAID WARNING",
                description=f"High join velocity detected: **{len(self.join_history)} joins** in the last minute.",
                color=discord.Color.orange(),
                timestamp=datetime.datetime.now(datetime.timezone.utc)
            )
            await self.log_to_channel(member.guild, log_embed)

async def setup(bot):
    await bot.add_cog(Protection(bot))
