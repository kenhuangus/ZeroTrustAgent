"""
Custom tools for CrewAI integration
"""

from typing import Any
from langchain_community.tools import DuckDuckGoSearchRun
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

class SecureSearchInput(BaseModel):
    """Input for the secure search tool."""
    query: str = Field(..., description="The search query to execute")

class SecureSearchTool(BaseTool):
    """A secure web search tool that uses DuckDuckGo."""
    name: str = "web_search"
    description: str = "Search the internet for information using DuckDuckGo"
    input_schema = SecureSearchInput

    def __init__(self):
        super().__init__()
        self._search_tool = DuckDuckGoSearchRun()

    def _execute(self, query: str) -> Any:
        """Execute the search query."""
        try:
            result = self._search_tool.run(query)
            return result
        except Exception as e:
            return f"Error performing search: {str(e)}"