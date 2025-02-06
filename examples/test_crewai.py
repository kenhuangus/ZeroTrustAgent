
from crewai import Agent, Task, Crew
from zta_agent import initialize_agent

def test_crewai_integration():
    # Initialize ZTA components
    print("Initializing Zero Trust Security Agent...")
    zta_components = initialize_agent()
    auth_manager = zta_components['auth_manager']
    crewai_adapter = zta_components['crewai_adapter']
    
    # Get authentication token
    print("\nTesting Authentication...")
    token = auth_manager.authenticate({
        "identity": "researcher",
        "secret": "test_secret"
    })
    print(f"Authentication token obtained successfully")
    
    # Test different task types
    tasks = [
        {
            "id": "research_task_1",
            "type": "research",
            "description": "Research AI security patterns"
        },
        {
            "id": "analysis_task_1",
            "type": "analysis",
            "description": "Analyze security findings"
        }
    ]
    
    print("\nTesting Task Execution...")
    for task in tasks:
        result = crewai_adapter.secure_task_execution(
            task=task,
            agent_id="researcher",
            token=token
        )
        print(f"Task {task['id']} execution allowed: {result}")
    
    # Test agent communication
    print("\nTesting Agent Communication...")
    messages = [
        {"type": "text", "content": "Research findings"},
        {"type": "command", "content": "analyze_data()"}
    ]
    
    for msg in messages:
        comm_result = crewai_adapter.validate_agent_communication(
            source_agent="researcher",
            target_agent="analyst",
            message=msg,
            token=token
        )
        print(f"Agent communication for {msg['type']} message allowed: {comm_result}")

if __name__ == "__main__":
    test_crewai_integration()
