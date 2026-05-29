-- Create databases for LangGraph checkpoints, LiteLLM spend tracking, and long-term memory
CREATE DATABASE langgraph;
CREATE DATABASE litellm;
CREATE DATABASE pentest_memory;

-- Enable pgvector in the memory DB
\connect pentest_memory
CREATE EXTENSION IF NOT EXISTS vector;
