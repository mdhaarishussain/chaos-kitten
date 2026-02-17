"""Rate Limiting & Retry Metrics Logging Guide.

This document describes how to configure logging for rate limit and retry events
in Chaos Kitten's executor module.
"""

## Logging Configuration

The executor uses Python's standard `logging` module to track rate limit events
and retry behavior. Configure logging in your application:

```python
import logging
import sys

# Configure root logger
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

# Optionally set specific log level for executor
executor_logger = logging.getLogger('chaos_kitten.paws.executor')
executor_logger.setLevel(logging.DEBUG)
```

## Log Events

The executor logs the following events:

### Rate Limited (429 Responses)

```
WARNING - chaos_kitten.paws.executor - Rate limited (429) - Retry-After: 5s (attempt 1)
```

This indicates:
- Server returned HTTP 429 (Too Many Requests)
- Suggests waiting 5 seconds before retry
- This is attempt 1 of the configured max_attempts

### Server Errors (5xx)

```
WARNING - chaos_kitten.paws.executor - Retrying after 0.10s (attempt 1/5)
```

Indicates retry is happening with the calculated backoff time.

### Timeout

```
ERROR - chaos_kitten.paws.executor - Request timeout after 30s: <error_details>
```

Connection timed out, executor will retry if attempts remain.

### Connection Error

```
ERROR - chaos_kitten.paws.executor - Connection error: <error_details>
```

Failed to connect to the target server.

## Metrics API

After execution, retrieve metrics:

```python
from chaos_kitten.paws.executor import Executor

async with Executor(base_url="http://api.example.com") as executor:
    await executor.execute_attack(method="GET", path="/test")
    
    metrics = executor.get_metrics()
    
    # Print metrics
    print(f"Total requests: {metrics['total_requests']}")
    print(f"Rate limited: {metrics['rate_limited_requests']}")
    print(f"Successful retries: {metrics['successful_retries']}")
    print(f"Failed retries: {metrics['failed_retries']}")
    print(f"Total backoff time: {metrics['total_backoff_time_ms']}ms")
    print(f"Rate limit rate: {metrics['rate_limit_rate']:.1%}")
    print(f"Retry-After headers seen: {metrics['retry_after_headers_seen']}")
```

### Metrics Explained

| Metric | Description |
|--------|-------------|
| `total_requests` | Total number of requests attempted |
| `rate_limited_requests` | How many responses had HTTP 429 status |
| `retried_requests` | How many requests were retried |
| `successful_retries` | Retries that eventually succeeded |
| `failed_retries` | Retries that failed after max attempts |
| `total_backoff_time_ms` | Total time spent waiting between retries |
| `rate_limit_rate` | Percentage of requests that hit rate limit |
| `retry_after_headers_seen` | Dictionary of Retry-After values and their counts |

## Integration with Monitoring Systems

### Export to Prometheus

```python
from prometheus_client import Counter, Histogram

# Define metrics
rate_limit_counter = Counter(
    'chaos_kitten_rate_limited_total',
    'Total rate limited responses',
    ['target']
)

backoff_histogram = Histogram(
    'chaos_kitten_backoff_duration_ms',
    'Backoff duration in milliseconds',
    ['strategy']
)

# After execution
metrics = executor.get_metrics()
rate_limit_counter.labels(target='api.example.com').inc(
    metrics['rate_limited_requests']
)
```

### Send to DataDog/New Relic

```python
import statsd

client = statsd.StatsClient('localhost', 8125)

metrics = executor.get_metrics()
client.gauge('chaos_kitten.rate_limit_rate', metrics['rate_limit_rate'] * 100)
client.gauge('chaos_kitten.backoff_time_ms', metrics['total_backoff_time_ms'])
client.gauge('chaos_kitten.successful_retries', metrics['successful_retries'])
```

## Best Practices

1. **Monitor Rate Limit Rate**: If >5% of requests are rate limited, consider:
   - Increasing `rate_limit` delay between requests
   - Reducing concurrent executor instances
   - Batching requests differently

2. **Track Backoff Time**: If `total_backoff_time_ms` is very high, the target
   is rate limiting aggressively:
   - Use adaptive backoff strategy
   - Consider spreading requests over longer time
   - Check if target has published rate limit documentation

3. **Log Retry-After Values**: Different targets use different values:
   - Some use seconds, others use timestamps
   - Track patterns to understand target behavior
   - Report to metrics system for trending

4. **Set Appropriate Max Attempts**: 
   - Default 5 attempts is good for most cases
   - Reduce for strict timeouts (e.g., 3 attempts)
   - Increase for flaky networks (e.g., 7 attempts)

## Troubleshooting

### High Rate Limit Rate

If you're seeing many 429 responses:

1. Check executor rate_limit setting:
   ```python
   executor = Executor(base_url=url, rate_limit=5)  # 5 req/s
   ```

2. Adjust retry configuration:
   ```yaml
   retry:
     strategy: adaptive  # Better for congestion
     jitter_factor: 0.3  # More randomness
   ```

3. Monitor server response times to ensure requests aren't piling up

### Excessive Backoff Time

If retries are waiting too long:

1. Use linear or adaptive strategy instead of exponential
2. Reduce max_backoff_ms:
   ```yaml
   retry:
     max_backoff_ms: 5000  # 5 seconds max
   ```

3. Check Retry-After header compliance - some servers may be wrong
4. Consider rate_limit parameter - leaving more time between requests

### All Retries Failing

If `failed_retries` is high:

1. Check if target is actually returning retryable status codes
2. May need to reduce `max_attempts` if target keeps rate limiting
3. Verify network connectivity and no firewall blocks
4. Check target's actual rate limit policy documentation

## Logging Examples

### Set Up File Logging

```python
import logging
from logging.handlers import RotatingFileHandler

# File handler for rate limit events
file_handler = RotatingFileHandler(
    'chaos_kitten_rate_limits.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.WARNING)

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
file_handler.setFormatter(formatter)

logger = logging.getLogger('chaos_kitten.paws.executor')
logger.addHandler(file_handler)
```

### Debug Mode

Enable detailed debugging:

```python
import logging

logging.basicConfig(level=logging.DEBUG)

async with Executor(base_url=url) as executor:
    await executor.execute_attack(...)
    # Will print detailed logs of all backoff calculations
```

## Related Documentation

- [Executor Configuration](../README.md#configuration)
- [Retry Strategies](../README.md#retry-logic--rate-limiting)
- [Response Analysis](analyzer.md)
