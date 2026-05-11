import asyncio
import httpx
from unittest.mock import patch
import ai_analyst.worker as worker_module
from ai_analyst.worker import process_next_ai_job
from test_ai_analyst_worker import FakeRepository, build_job, build_provider

async def main():
    job = build_job()
    provider = build_provider(is_local=False, configured=True)
    repository = FakeRepository(job=job, provider=provider)
    
    # Mock OpenRouter success response
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"observed_behavior": ["b1"], "inference": ["i1"], "limitations": ["l1"]}'
                        }
                    }
                ]
            }
        )
    
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    
    with patch('ai_analyst.worker.validate_ai_explanation_schema', side_effect=RuntimeError('ai explanation schema validation failed: model is not allowed in test validator')):
        response = await process_next_ai_job(
            repository,
            http_client=http_client
        )
        
        # We need to print the values as requested.
        # response.state, repository.degraded, repository.failed
        print(f"response.state: {response.state}")
        print(f"repository.degraded: {repository.degraded}")
        print(f"repository.failed: {repository.failed}")

if __name__ == "__main__":
    asyncio.run(main())
