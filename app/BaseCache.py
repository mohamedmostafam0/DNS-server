import redis
import time
import pickle
from typing import Optional
import hashlib
import logging
from utils import parse_question_section, parse_dns_query


class BaseCache:
    def __init__(self, redis_host, redis_port, db):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        # print("Cache connection initialized")

    def get(self, cache_key: tuple, transaction_id: int) -> Optional[bytes]:
            """
            Retrieves the DNS query response from the cache if it exists and is still valid (TTL not expired),
            ensuring the transaction ID matches the client's query.
            """
            # Serialize the cache key to a string
            key_string = self._serialize_cache_key(cache_key)
            cached_data = self.client.get(key_string)
            logging.info(f"Cache key: {key_string}, cached_data: {cached_data}")

            if cached_data:
                try:
                    cached_response = pickle.loads(cached_data)
                except Exception as e:
                    logging.error(f"Error deserializing cache data: {e}")
                    return None

                if cached_response['ttl'] > time.time():
                    try:
                        # Parse the cached response to extract details and ensure integrity
                        cached_transaction_id, domain_name, qtype, qclass = parse_dns_query(cached_response['response'])
                        # logging.info(f"Cached transaction ID: {cached_transaction_id}, Domain: {domain_name}, Qtype: {qtype}, Qclass: {qclass}")


                        # Modify the cached response to include the new transaction ID
                        response = bytearray(cached_response['response'])  # Convert to mutable bytearray
                        response[0:2] = transaction_id.to_bytes(2, byteorder='big')  # Update transaction ID

                        # logging.info(f"Updated transaction ID in response for domain: {domain_name}")
                        return bytes(response)  # Convert back to bytes and return
                    except ValueError as e:
                        logging.error(f"Error parsing cached DNS response: {e}")
                        return None
                else:
                    # Cache entry expired, delete it
                    self.client.delete(key_string)
                    logging.info(f"Cache expired for key: {key_string}")

            return None

    def store(self, response: bytes):
        # logging.info(f"storing response in cache")
        ttl = 3600
        try:
            qname, qtype, qclass, _ = parse_question_section(response, 12)
            qname = qname.lower()  # Normalize domain to lowercase
            cache_key = (qname, qtype, qclass)

            key_string = self._serialize_cache_key(cache_key)

            cache_entry = {
                'response': response,
                'ttl': time.time() + ttl
            }

            self.client.setex(key_string, ttl, pickle.dumps(cache_entry))
#            logging.info(f"Stored in cache: Key={key_string}, TTL={ttl}, Entry={cache_entry}")
        except Exception as e:
            logging.error(f"Error storing response in cache: {e}")

    def _serialize_cache_key(self, cache_key: tuple) -> str:
        """
        Serializes a tuple cache key into a string format suitable for Redis.

        Parameters:
            cache_key (tuple): The cache key as (domain_name, qtype, qclass).

        Returns:
            str: A serialized string suitable for Redis.
        """
        return f"dns:{hashlib.sha256(':'.join(map(str, cache_key)).encode()).hexdigest()}"
