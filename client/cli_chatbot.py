#!/usr/bin/env python3
"""
CLI Interactive Chatbot for SecureMCP.
Allows chatting with SecureMCP directly in terminal.
"""

import sys
from mcp_client import SecureMcpClient
from chatbot import SecureMcpChatbot


def main():
    print("=" * 60)
    print(" 🛡️  SecureMCP Interactive Terminal Chatbot")
    print("=" * 60)
    print("Authenticating against http://localhost:8080...")

    client = SecureMcpClient()
    try:
        token = client.get_token()
        print(f"✅ OAuth2 Authentication Successful (Token: {token[:16]}...)")
        client.connect_and_initialize()
        print(f"✅ Connected to MCP Session: {client.session_id}")
        print(f"✅ Loaded {len(client.tools)} SecureMCP Tools")
    except Exception as e:
        print(f"❌ Connection error: {e}")
        sys.exit(1)

    bot = SecureMcpChatbot(client)
    print("\nType 'help' to see sample queries, or 'exit'/'quit' to leave.\n")

    while True:
        try:
            user_msg = input("\n👤 You: ").strip()
            if not user_msg:
                continue
            if user_msg.lower() in ["exit", "quit"]:
                print("Goodbye!")
                break

            response = bot.process_message(user_msg)
            print("\n🤖 Bot:")
            print(response["reply"])
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break


if __name__ == "__main__":
    main()
