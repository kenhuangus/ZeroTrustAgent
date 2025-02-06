
from crewai import Agent, Task, Crew
from zta_agent import initialize_agent

def test_crewai_integration():
    # Initialize ZTA components
    zta_components = initialize_agent()
    auth_manager = zta_components['auth_manager']
    crewai_adapter = zta_components['crewai_adapter']
    
    # Get authentication token
    token = auth_manager.authenticate({
        "identity": "researcher",
        "secret": "test_secret"
    })
    
    # Create test task
    task_data = {
        "id": "research_task_1",
        "type": "research",
        "description": "Research AI security patterns"
    }
    
    # Test secure execution
    result = crewai_adapter.secure_task_execution(
        task=task_data,
        agent_id="researcher",
        token=token
    )
    
    print(f"CrewAI Integration Test Result: {result}")

if __name__ == "__main__":
    test_crewai_integration()
