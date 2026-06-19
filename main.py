"""
main.py — Agent Security Checker
Runs all 4 agents (Discovery, Attack, Report, Dummy Target)
Agents sit and wait for commands in Band room.
Auto-restarts if any agent crashes.
"""

import asyncio
import sys
import threading
import logging
import os
import time

# ============================================================
# SETUP
# ============================================================

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [Main] %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

IS_DEPLOYED = os.environ.get("REPLIT_DEPLOYMENT") == "1"

# ============================================================
# FLASK DUMMY TARGET (Runs in a separate thread)
# ============================================================


def run_flask():
    """Start the dummy target agent on port 5000."""
    try:
        from dummy_target_agent import app

        logger.info("🚀 Starting Flask dummy target on port 5000...")
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"❌ Flask failed to start: {e}")


# ============================================================
# AGENT SUBPROCESS MANAGER (Auto-restart)
# ============================================================


async def run_agent(script: str):
    """
    Run a Python agent script as a subprocess.
    If it crashes or exits, it automatically restarts after 5 seconds.
    This keeps the agent "sitting" and always available.
    """
    restart_delay = 5

    while True:
        logger.info(f"▶ Starting {script}...")

        # Start the subprocess
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=os.getcwd(),
        )

        # Stream output line by line
        async for line in process.stdout:
            print(f"[{script}] {line.decode().rstrip()}", flush=True)

        # Wait for process to exit
        await process.wait()

        if process.returncode == 0:
            logger.info(f"{script} exited cleanly — restarting in {restart_delay}s...")
        else:
            logger.warning(
                f"{script} exited with code {process.returncode} — restarting in {restart_delay}s..."
            )

        await asyncio.sleep(restart_delay)


async def run_agent_with_timeout(script: str, timeout: int = 30):
    """
    Run agent but if it exits immediately (like with config error),
    log it and don't spam restarts.
    """
    restart_delay = 10
    first_run = True

    while True:
        if first_run:
            logger.info(f"▶ Starting {script}...")
            first_run = False
        else:
            logger.info(f"🔄 Restarting {script} in {restart_delay}s...")
            await asyncio.sleep(restart_delay)

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=os.getcwd(),
        )

        # Stream output
        async for line in process.stdout:
            print(f"[{script}] {line.decode().rstrip()}", flush=True)

        await process.wait()

        if process.returncode != 0:
            logger.warning(f"{script} exited with code {process.returncode}")


# ============================================================
# MAIN ORCHESTRATION
# ============================================================


async def main():
    print("=" * 70)
    print("  🛡️  AGENT SECURITY CHECKER — All 4 Agents Sitting")
    print("=" * 70)
    print("\n📡 Starting agents...")
    print("   • Discovery Agent  → Waiting for 'scan' command")
    print("   • Attack Agent     → Waiting for 'DISCOVERY COMPLETE'")
    print("   • Report Agent     → Waiting for 'attack complete'")
    print("   • Dummy Target     → Waiting for HTTP requests")
    print("\n🟢 All agents will sit and listen on Band.\n")

    # ── Start Flask dummy target ──────────────────────────────────
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("✅ Dummy Target thread started (port 5000)")

    # Wait for Flask to initialize
    await asyncio.sleep(2)

    # ── Production mode: only run Flask ──────────────────────────
    if IS_DEPLOYED:
        logger.info("☁️  Running in PRODUCTION mode (agents run locally)")
        logger.info("    Dummy target is live on port 5000.")
        logger.info("    Press Ctrl+C to stop.\n")

        # Keep the process alive
        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            pass
        return

    # ── Development mode: run all 4 agents ──────────────────────
    logger.info("🚀 Starting all 3 Band agents (they will sit and wait)...")
    logger.info("   Agents will auto-restart if they crash.\n")

    # Run all agents concurrently
    try:
        await asyncio.gather(
            run_agent("discovery_agent.py"),
            run_agent("attack_agent.py"),
            run_agent("report_agent.py"),
        )
    except asyncio.CancelledError:
        logger.info("Shutting down agents...")
    except KeyboardInterrupt:
        logger.info("Shutting down...")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 All agents stopped.")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
