"""
Custom tools for CrewAI integration
"""

from typing import Any, Dict
from langchain_community.tools import DuckDuckGoSearchRun
from crewai.tools import BaseTool
from pydantic.v1 import BaseModel, Field
from tenacity import retry, wait_exponential, stop_after_attempt
import logging

logger = logging.getLogger(__name__)

class SecureSearchInput(BaseModel):
    """Input for the secure search tool."""
    query: str = Field(..., description="The search query to execute")

class SecureSearchTool(BaseTool):
    """A secure web search tool that uses DuckDuckGo."""
    name: str = "web_search"
    description: str = "Search the internet for information using DuckDuckGo"
    args_schema: BaseModel = SecureSearchInput

    def __init__(self):
        super().__init__()
        self._search_tool = DuckDuckGoSearchRun()

    @retry(
        wait=wait_exponential(multiplier=2, min=4, max=60),
        stop=stop_after_attempt(3),
        reraise=True
    )
    def _run(self, query: str) -> str:
        """Execute the search query with retry logic."""
        try:
            logger.info(f"Executing search query: {query}")
            result = self._search_tool.run(query)
            logger.info("Search completed successfully")
            return result
        except Exception as e:
            logger.error(f"Error performing search: {str(e)}")
            raise