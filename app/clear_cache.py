import subprocess

def clear_redis_cache(server_name):
    try:
        print(f"Clearing cache for {server_name}...")
        # Execute the Redis flushdb command inside the container
        result = subprocess.run(
            ["docker", "exec", "-i", server_name, "redis-cli", "flushdb"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            print(f"Cache cleared successfully for {server_name}.")
        else:
            print(f"Failed to clear cache for {server_name}: {result.stderr}")
    except Exception as e:
        print(f"Error clearing cache for {server_name}: {e}")

# List of Redis servers
servers = ["redis-server-1", "redis-server-2", "redis-server-3"]

# Clear cache for each server
for server in servers:
    clear_redis_cache(server)
