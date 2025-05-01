"""
Functionality:  LangGraph Agent Example for ZTA/ "ZeroTrustAgent"  Agentic Authentication Framework

This example demonstrates how to use LangGraph Agent to define a simple agent workflow
that analyzes user access requests in a Zero Trust agent model and decides whether to approve or deny access.

Output:
    Results are logged and persisted to langgraph_agent_output.json

# @Author: Akram Sheriff 
# Date:  30th of  April 2025
"""

import os
import json
import logging
from typing import TypedDict, Literal

from langchain.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv

# -- Setup logging --
logging.basicConfig(
    filename="langgraph_agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# -- Load env vars --
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    logging.error("OPENAI_API_KEY not set. Please set it in your environment or .env file.")
    raise EnvironmentError("OPENAI_API_KEY not set.")

# -- State definition --
class AgentState(TypedDict):
    request: str
    reasoning: str
    decision: Literal["approved", "denied"]

# -- Tooling --
def access_policy_check(request: str) -> str:
    """
    Mock tool to analyze access request sensitivity.
    """
    if "admin" in request.lower() or "sensitive" in request.lower():
        return "Request involves high-privilege access. Extra scrutiny required."
    return "Request appears to be low-privilege. No red flags found."

# -- LLM initialization --
llm = ChatOpenAI(model="gpt-4", temperature=0)

# -- LangGraph Node: Analyze request --
def analyze_request(state: AgentState) -> AgentState:
    logging.info("Analyzing request...")
    messages = [
        SystemMessage(content="You are a Zero Trust security assistant."),
        HumanMessage(content=f"Analyze this access request:\n{state['request']}"),
    ]
    response = llm(messages).content
    state["reasoning"] = response
    logging.info(f"Reasoning generated: {response}")
    return state

# -- LangGraph Node: Make decision --
def decide_access(state: AgentState) -> AgentState:
    logging.info("Deciding access based on reasoning...")
    if "high-privilege" in state["reasoning"].lower():
        state["decision"] = "denied"
    else:
        state["decision"] = "approved"
    logging.info(f"Access decision: {state['decision']}")
    return state

# -- Build LangGraph --
graph = StateGraph(AgentState)
graph.add_node("Analyze", analyze_request)
graph.add_node("Decide", decide_access)

graph.set_entry_point("Analyze")
graph.add_edge("Analyze", "Decide")
graph.add_edge("Decide", END)

app = graph.compile()

# -- Output persistence helper --
def persist_output(state: AgentState, output_path: str):
    try:
        with open(output_path, "w") as f:
            json.dump(state, f, indent=4)
        logging.info(f"Output persisted to {output_path}")
    except Exception as e:
        logging.error(f"Error writing output JSON: {e}")

# -- Main script execution --
if __name__ == "__main__":
    example_input = {
        "request": "User John requests access to the admin dashboard for compliance data",
        "reasoning": "",
        "decision": "",
    }

    logging.info("Starting LangGraph agent...")
    final_state = app.invoke(example_input)
    print("Final Output:")
    print(json.dumps(final_state, indent=4))

    persist_output(final_state, "langgraph_agent_output.json")
