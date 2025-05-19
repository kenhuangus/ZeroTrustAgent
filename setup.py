from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='zta-agent',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        "anthropic>=0.45.2",
        "crewai>=0.11.0",
        "duckduckgo-search>=4.1.1",
        "google-cloud-aiplatform>=1.79.0",
        "google-generativeai>=0.8.4",
        "langchain>=0.1.0",
        "langchain-community>=0.0.10",
        "langchain-google-vertexai>=2.0.7",
        "langchain-ollama>=0.2.3",
        "langchain-openai>=0.0.2",
        "litellm>=1.59.8",
        "openai>=1.0.0",
        "pyautogen>=0.7.3",
        "pydantic>=2.10.6",
        "pyjwt>=2.10.1",
        "python-dotenv>=1.0.1",
        "pyyaml>=6.0.2",
        "tenacity>=9.0.0",
        "vertexai>=1.43.0",
    ],
    extras_require={
        'dev': [
            'pytest',
            'flake8',
        ],
    },
    entry_points={
        'console_scripts': [
            # If you have any command-line scripts:
            # 'my_script = my_package.module:main',
        ],
    },
    author='Ken Huang',
    author_email='ken.huang@distributedapps.ai',
    description='Zero Trust Agent (ZTA) Framework for Multi-Agent Collaboration',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/distributedapps-ai/zta-agent',  # Update URL
    license='MIT',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.11', #Update python version
)
