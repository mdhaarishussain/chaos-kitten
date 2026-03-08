"""Tests for attack_chainer.py."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from chaos_kitten.brain.attack_chainer import EndpointGraph, AttackChainPlanner, ChainExecutor

@pytest.fixture
def sample_endpoints():
    return [
        {
            "method": "POST",
            "path": "/users",
            "parameters": [],
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {
                                "name": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "responses": {
                "201": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "id": {"type": "integer"},
                                    "token": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        },
        {
            "method": "GET",
            "path": "/users/{id}/orders",
            "parameters": [
                {"name": "id", "in": "path"}
            ],
            "responses": {
                "200": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "order_id": {"type": "integer"}
                                }
                            }
                        }
                    }
                }
            }
        },
        {
            "method": "DELETE",
            "path": "/orders/{order_id}",
            "parameters": [
                {"name": "order_id", "in": "path"}
            ],
            "responses": {
                "204": {}
            }
        }
    ]

def test_endpoint_graph(sample_endpoints):
    graph = EndpointGraph(sample_endpoints)
    
    # Check edges
    # Endpoint 0 produces 'id', Endpoint 1 consumes 'id'
    assert len(graph.graph[0]) == 1
    assert graph.graph[0][0]["target"] == 1
    assert graph.graph[0][0]["field"] == "id"
    
    # Endpoint 1 produces 'order_id', Endpoint 2 consumes 'order_id'
    assert len(graph.graph[1]) == 1
    assert graph.graph[1][0]["target"] == 2
    assert graph.graph[1][0]["field"] == "order_id"
    
    summary = graph.get_graph_summary()
    assert "[0] POST /users" in summary
    assert "Feeds into: [1] (via id)" in summary
    assert "[1] GET /users/{id}/orders" in summary
    assert "Feeds into: [2] (via order_id)" in summary

@pytest.mark.asyncio
async def test_attack_chain_planner(sample_endpoints):
    mock_llm = MagicMock()
    mock_chain = AsyncMock()
    mock_chain.ainvoke.return_value = [
        {
            "name": "Test Chain",
            "description": "Test",
            "steps": []
        }
    ]
    
    with patch("chaos_kitten.brain.attack_chainer.ChatPromptTemplate") as mock_prompt:
        mock_prompt.from_template.return_value.__or__.return_value.__or__.return_value = mock_chain
        
        planner = AttackChainPlanner(mock_llm)
        chains = await planner.plan_chains(sample_endpoints)
        
        assert len(chains) == 1
        assert chains[0]["name"] == "Test Chain"

@pytest.mark.asyncio
async def test_attack_chain_planner_error(sample_endpoints):
    mock_llm = MagicMock()
    mock_chain = AsyncMock()
    mock_chain.ainvoke.side_effect = Exception("LLM Error")
    
    with patch("chaos_kitten.brain.attack_chainer.ChatPromptTemplate") as mock_prompt:
        mock_prompt.from_template.return_value.__or__.return_value.__or__.return_value = mock_chain
        
        planner = AttackChainPlanner(mock_llm)
        chains = await planner.plan_chains(sample_endpoints)
        
        assert chains == []

@pytest.mark.asyncio
async def test_chain_executor():
    mock_executor = AsyncMock()
    
    # Mock responses for each step
    mock_executor.execute_attack.side_effect = [
        {"status_code": 201, "body": '{"id": 42}'},
        {"status_code": 200, "body": '{"order_id": 99}'},
        {"status_code": 204, "body": ""}
    ]
    
    chain = {
        "steps": [
            {
                "method": "POST",
                "path": "/users",
                "extracts": {"id": "user_id"},
                "injects": {}
            },
            {
                "method": "GET",
                "path": "/users/{user_id}/orders",
                "extracts": {"order_id": "order_id"},
                "injects": {}
            },
            {
                "method": "DELETE",
                "path": "/orders/{order_id}",
                "extracts": {},
                "injects": {}
            }
        ]
    }
    
    executor = ChainExecutor(mock_executor)
    result = await executor.execute_chain(chain, "http://localhost")
    
    assert len(result["results"]) == 3
    
    # Check that variables were substituted correctly
    calls = mock_executor.execute_attack.call_args_list
    assert calls[0][0][1] == "/users"
    assert calls[1][0][1] == "/users/42/orders"
    assert calls[2][0][1] == "/orders/99"
