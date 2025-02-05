import redis
from BaseCache import BaseCache

# class ResolverCache(BaseCache):
#     def __init__(self, redis_host="localhost", redis_port=6379, db=0):
#         """
#         Initializes the Redis cache connection.
#         """
#         self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
#         print("Resolver Cache connection initialized")

class ResolverCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6379, db=0):
        super().__init__(redis_host, redis_port, db)  # Call BaseCache constructor
        print("Resolver Cache connection initialized")
