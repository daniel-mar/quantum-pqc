TLDR: Post Quantum Cryptography DOCKER environment, Testing PQC API Routing and TestSuites for success/edge-cases.
- Enforce specific input (REGEX), Sanitise / Validate input before sending data to OQS, Exception handling error codes.

Project began from wanting to expand on my Quantum Computing understanding and move towards Post Quantum Cryptography.

From test files to main.py file with FastAPI to create and test routes before introducing a front-end

I wanted to run this application on my local machine and remembered I learned Docker to handle environment and versioning.
I explored Dockerfiles and devcontainer.json to be able to share this project with ease and scale it out.

Clone the project and within VSCode (bottom-left) click on the >< button
- Click Reopen in Container

Wait for the container to load and enter your venv within the VSCode console if it has not automatically done so,
install dependencies NOTE: (oqs may not be needed to be installed as the Docker scripts are made to create an environment for OQS / lib-oqs (open quantum safe) within the linux environment
this is the main reason for moving to Docker instead of building locally, to fix the pathing and begin to build applications through NIST standards. 

Dependencies 
- pip install fastpi pydantic oqs 

Within test folder
- pip install pytest httpx2

Should be ready to test the functionality of the API within main.py

You can test the functionality by running
- python3 test/test_api.py
  or for debugging additional tests
- python3 -s test/test_api.py

I created the Dockerfile, devcontainer.json to have an environment to test PQC, and I wanted to see how to refine the back-end before building a front-end.
Might adjust that or create a requirements.txt for the environment.
