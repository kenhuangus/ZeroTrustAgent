
from crewai import Agent, Task, Crew
from zta_agent import initialize_agent

# Initialize ZTA components
zta_components = initialize_agent()
crewai_adapter = zta_components['crewai_adapter']

# Create a secure agent with ZTA validation
def create_secure_agent(agent_id: str, token: str):
    # Define the agent
    agent = Agent(
        name=agent_id,
        goal="Perform research tasks",
        backstory="AI researcher assistant",
        allow_delegation=False
    )
    
    # Wrap agent actions with security
    original_execute = agent.execute
    def secure_execute(task):
        # Validate the task execution
        secured_task = crewai_adapter.secure_task_execution(
            task={'id': task.id, 'type': 'research'},
            agent_id=agent_id,
            token=token
        )
        if secured_task:
            return original_execute(task)
        return "Access denied"
    
    agent.execute = secure_execute
    return agent

# Example usage
if __name__ == "__main__":
    # Get token for authentication
    auth_manager = zta_components['auth_manager']
    token = auth_manager.authenticate({
        "identity": "research_agent",
        "secret": "secret123"
    })
    
    # Create secure agents
    researcher = create_secure_agent("research_agent", token)
    analyst = create_secure_agent("analyst_agent", token)
    
    # Create tasks
    research_task = Task(
        description="Research AI security",
        agent=researcher
    )
    
    analysis_task = Task(
        description="Analyze findings",
        agent=analyst
    )
    
    # Create and run crew
    crew = Crew(
        agents=[researcher, analyst],
        tasks=[research_task, analysis_task]
    )
    
    result = crew.kickoff()
    print("Crew execution result:", result)
