from http.client import HTTPSConnection
from json import dumps
import os
import hmac
import hashlib

def verify_signature(body: bytes, signature_header: str, webhook_secret: str) -> bool:
    """Verify the Neynar webhook signature"""
    if not signature_header or not webhook_secret:
        return False
    
    expected_signature = hmac.new(
        webhook_secret.encode('utf-8'),
        body,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature_header, expected_signature)

def handler(request):
    """Handle incoming webhook requests"""
    # Get environment variables
    WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')
    DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')
    
    # Check if environment variables are set
    if not WEBHOOK_SECRET or not DISCORD_WEBHOOK_URL:
        return {
            'statusCode': 500,
            'body': 'Missing environment variables'
        }

    try:
        # Verify Neynar signature
        signature = request.headers.get('x-neynar-signature')
        if not verify_signature(request.body, signature, WEBHOOK_SECRET):
            return {
                'statusCode': 401,
                'body': 'Invalid signature'
            }

        # Parse the incoming webhook data
        event_data = request.json()
        
        # Only process cast.created events
        if event_data.get('type') != 'cast.created':
            return {
                'statusCode': 200,
                'body': 'Event type ignored'
            }

        # Extract cast data
        cast = event_data.get('data', {})
        author = cast.get('author', {})

        # Create Discord message embed
        discord_payload = {
            "embeds": [{
                "color": 0x7B3FE4,  # Purple color
                "author": {
                    "name": f"{author.get('display_name')} (@{author.get('username')})",
                    "icon_url": author.get('pfp_url')
                },
                "description": cast.get('text'),
                "fields": [
                    {
                        "name": "Followers",
                        "value": str(author.get('follower_count', 0)),
                        "inline": True
                    },
                    {
                        "name": "Following",
                        "value": str(author.get('following_count', 0)),
                        "inline": True
                    }
                ],
                "timestamp": cast.get('timestamp'),
                "footer": {
                    "text": f"FID: {author.get('fid')} • Hash: {cast.get('hash', '')[:10]}..."
                }
            }]
        }

        # Add parent information if it's a reply
        if cast.get('parent_hash'):
            discord_payload["embeds"][0]["fields"].append({
                "name": "Replying to",
                "value": f"Cast {cast.get('parent_hash')[:10]}...",
                "inline": False
            })

        # Parse Discord webhook URL
        discord_url = DISCORD_WEBHOOK_URL.replace('https://', '').split('/')
        discord_host = discord_url[0]
        discord_path = '/' + '/'.join(discord_url[1:])

        # Send to Discord
        conn = HTTPSConnection(discord_host)
        conn.request(
            "POST",
            discord_path,
            dumps(discord_payload),
            {
                "Content-Type": "application/json",
            }
        )
        response = conn.getresponse()
        conn.close()

        if response.status not in [200, 204]:
            return {
                'statusCode': 500,
                'body': 'Failed to send to Discord'
            }

        return {
            'statusCode': 200,
            'body': 'Success'
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': str(e)
        }
