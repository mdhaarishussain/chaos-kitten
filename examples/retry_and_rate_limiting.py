"""Example: Using Chaos Kitten with Retry Logic.

This example demonstrates how to use the executor with rate limiting
and automatic retry capabilities.
"""

import asyncio
import logging
from chaos_kitten.paws.executor import Executor, RetryConfig, RetryStrategy

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


async def example_basic_usage():
    """Basic usage with default retry settings."""
    logger.info("=== Basic Usage Example ===")
    
    async with Executor(base_url="http://httpbin.org") as executor:
        # Make a GET request (will auto-retry on 429, 5xx)
        result = await executor.execute_attack(
            method="GET",
            path="/status/200"
        )
        
        print(f"Status: {result['status_code']}")
        print(f"Error: {result['error']}")
        print(f"Response time: {result['elapsed_ms']:.2f}ms")


async def example_rate_limiting():
    """Demonstrate rate limiting."""
    logger.info("=== Rate Limiting Example ===")
    
    # Limit to 2 requests per second
    async with Executor(
        base_url="http://httpbin.org",
        rate_limit=2
    ) as executor:
        print("Making 4 requests at 2 req/s (should take ~2 seconds)...")
        start = asyncio.get_event_loop().time()
        
        for i in range(4):
            result = await executor.execute_attack(
                method="GET",
                path=f"/delay/{i}"
            )
            elapsed = asyncio.get_event_loop().time() - start
            print(f"Request {i+1}: {result['status_code']} (elapsed: {elapsed:.2f}s)")


async def example_custom_retry_config():
    """Use custom retry configuration."""
    logger.info("=== Custom Retry Config Example ===")
    
    # Custom retry config with linear backoff
    retry_config = RetryConfig(
        max_attempts=4,
        initial_backoff_ms=200,
        max_backoff_ms=2000,
        strategy=RetryStrategy.LINEAR,  # Linear instead of exponential
        jitter_factor=0.2,
        respect_retry_after=True
    )
    
    async with Executor(
        base_url="http://httpbin.org",
        retry_config=retry_config
    ) as executor:
        # This will use linear backoff: 200ms, 400ms, 600ms
        result = await executor.execute_attack(
            method="GET",
            path="/status/200"
        )
        
        print(f"Result: {result['status_code']}")
        
        # Get metrics
        metrics = executor.get_metrics()
        print(f"\nMetrics:")
        print(f"  Total requests: {metrics['total_requests']}")
        print(f"  Rate limited: {metrics['rate_limited_requests']}")
        print(f"  Successful retries: {metrics['successful_retries']}")
        print(f"  Total backoff: {metrics['total_backoff_time_ms']:.2f}ms")


async def example_adaptive_backoff():
    """Use adaptive backoff for unpredictable servers."""
    logger.info("=== Adaptive Backoff Example ===")
    
    retry_config = RetryConfig(
        strategy=RetryStrategy.ADAPTIVE,
        initial_backoff_ms=100,
        max_backoff_ms=10000,
        jitter_factor=0.3  # More jitter for better distribution
    )
    
    async with Executor(
        base_url="http://httpbin.org",
        retry_config=retry_config
    ) as executor:
        # Adaptive strategy is good for servers that might be congested
        result = await executor.execute_attack(
            method="GET",
            path="/status/200"
        )
        
        print(f"Result: {result['status_code']}")


async def example_custom_headers_with_retry():
    """Make requests with custom headers AND automatic retry."""
    logger.info("=== Custom Headers with Retry Example ===")
    
    async with Executor(
        base_url="http://httpbin.org",
        auth_type="bearer",
        auth_token="example-token-123"
    ) as executor:
        result = await executor.execute_attack(
            method="POST",
            path="/post",
            payload={"key": "value"},
            headers={
                "X-Custom-Header": "my-value",
                "X-Request-ID": "12345"
            }
        )
        
        print(f"Status: {result['status_code']}")
        print(f"Response contains custom header info: {result['body'][:100]}...")


async def example_metrics_tracking():
    """Track metrics across multiple requests."""
    logger.info("=== Metrics Tracking Example ===")
    
    async with Executor(
        base_url="http://httpbin.org",
        rate_limit=5  # 5 requests per second
    ) as executor:
        # Make several requests
        for i in range(3):
            await executor.execute_attack(
                method="GET",
                path=f"/get?id={i}"
            )
        
        # Get comprehensive metrics
        metrics = executor.get_metrics()
        
        print("\n=== Execution Metrics ===")
        print(f"Total requests: {metrics['total_requests']}")
        print(f"Rate limited requests: {metrics['rate_limited_requests']}")
        print(f"Retried requests: {metrics['retried_requests']}")
        print(f"Successful retries: {metrics['successful_retries']}")
        print(f"Failed retries: {metrics['failed_retries']}")
        print(f"Total backoff time: {metrics['total_backoff_time_ms']:.2f}ms")
        print(f"Rate limit rate: {metrics['rate_limit_rate']:.1%}")
        
        if metrics['retry_after_headers_seen']:
            print(f"Retry-After headers seen: {metrics['retry_after_headers_seen']}")


async def example_fixed_backoff():
    """Use fixed backoff strategy."""
    logger.info("=== Fixed Backoff Example ===")
    
    retry_config = RetryConfig(
        strategy=RetryStrategy.FIXED,
        initial_backoff_ms=500,  # Always wait 500ms
        jitter_factor=0.1
    )
    
    async with Executor(
        base_url="http://httpbin.org",
        retry_config=retry_config
    ) as executor:
        result = await executor.execute_attack(
            method="GET",
            path="/status/200"
        )
        
        metrics = executor.get_metrics()
        print(f"Status: {result['status_code']}")
        print(f"Total backoff: {metrics['total_backoff_time_ms']:.2f}ms")
        print("(Note: With fixed strategy, each retry waits exactly 500ms)")


async def example_error_handling():
    """Demonstrate error handling with retries."""
    logger.info("=== Error Handling Example ===")
    
    async with Executor(
        base_url="http://httpbin.org"
    ) as executor:
        # Try a request that will likely fail
        result = await executor.execute_attack(
            method="GET",
            path="/status/429"  # This endpoint returns 429
        )
        
        if result['error']:
            print(f"Request failed: {result['error']}")
            print(f"Status code: {result['status_code']}")
        else:
            print(f"Request succeeded with status: {result['status_code']}")
        
        # Check metrics to see retry attempts
        metrics = executor.get_metrics()
        print(f"Retry attempts made: {metrics['retried_requests']}")
        print(f"Rate limited responses: {metrics['rate_limited_requests']}")


async def example_reset_metrics():
    """Show how to reset metrics between test runs."""
    logger.info("=== Reset Metrics Example ===")
    
    async with Executor(base_url="http://httpbin.org") as executor:
        # First batch of requests
        for _ in range(2):
            await executor.execute_attack(method="GET", path="/get")
        
        metrics1 = executor.get_metrics()
        print(f"First batch - Total requests: {metrics1['total_requests']}")
        
        # Reset metrics
        executor.reset_metrics()
        print("Metrics reset!")
        
        # Second batch of requests
        for _ in range(3):
            await executor.execute_attack(method="GET", path="/get")
        
        metrics2 = executor.get_metrics()
        print(f"Second batch - Total requests: {metrics2['total_requests']}")


async def main():
    """Run all examples."""
    print("╔════════════════════════════════════════════════════════╗")
    print("║  Chaos Kitten - Retry Logic & Rate Limiting Examples  ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    try:
        # Run examples
        await example_basic_usage()
        print("\n" + "="*50 + "\n")
        
        await example_rate_limiting()
        print("\n" + "="*50 + "\n")
        
        await example_custom_retry_config()
        print("\n" + "="*50 + "\n")
        
        await example_adaptive_backoff()
        print("\n" + "="*50 + "\n")
        
        await example_fixed_backoff()
        print("\n" + "="*50 + "\n")
        
        await example_metrics_tracking()
        print("\n" + "="*50 + "\n")
        
        await example_custom_headers_with_retry()
        print("\n" + "="*50 + "\n")
        
        await example_reset_metrics()
        
    except Exception as e:
        logger.error(f"Example failed: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
