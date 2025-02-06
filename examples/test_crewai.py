
from crewai import Agent, Task, Crew
from zta_agent import initialize_agent

def test_crewai_integration():
    # Initialize ZTA components
    zta_components = initialize_agent()
    crewai_adapter = zta_components['crewai_adapter']
    
    # Get authentication token
    auth_manager = zta_components['auth_manager']
    token = auth_manager.authenticate({
        "identity": "research_agent",
        "secret": "secret123"
    })
    
    # Create research agent with security
    researcher = Agent(
        name="research_agent",
        goal="Research AI security patterns",
        backstory="Expert in AI security research",
        allow_delegation=False
    )
    
    # Create research task
    research_task = Task(
        description="Analyze common security patterns in AI systems",
        agent=researcher
    )
    
    # Secure the task execution
    result = crewai_adapter.secure_task_execution(
        task={'id': research_task.id, 'type': 'research'},
        agent_id="research_agent",
        token=token
    )
    
    print(f"Secure task execution result: {result}")
    
if __name__ == "__main__":
    test_crewai_integration()
