from groq import Groq


from Red_Team_Functions.Enumeration import Gobuster
from Red_Team_Functions.Enumeration import  Nikto
from Red_Team_Functions.Enumeration import Nmap_Scanner
from Red_Team_Functions.Enumeration import Shodan
from Red_Team_Functions.Enumeration import Spiderfoot





from langchain_google_genai import ChatGoogleGenerativeAI
import logging
import os



import langchain
from langchain_core.tools import Tool
from langchain.memory import SimpleMemory
groq_api_key = "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"
client = Groq(api_key=groq_api_key)




class AI_Agent:
    def __init__(self):
        self.agent = AI_Agent()
        self.memory = SimpleMemory()


completion = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[
        {
            "role": "system",
            "content": "You are a cybersecurity specialist with an expertise on enunmeration and exploitation./"
                       "If a website address is given to you like https://google.com /"
                       "Use the tools provided to you to enumerate and exploit the given vulnerable application"


        },
        {
            "role": "user",
            "content": "Website: https://google.com "
        }
    ],
    temperature=1,
    max_completion_tokens=1024,
    top_p=1,
    stream=True,
    stop=None,
)

for chunk in completion:
    print(chunk.choices[0].delta.content or "", end="")



tools = [
    Tool(
        name="Gobuster",
        description="Gobuster is a directory enumeration tool looking for directories and virtual hosts",
        func = Gobuster,


    ),
    Tool(
        name="Nikto",
        description="Nikto is a directory enumeration tool looking for directories and virtual hosts",
        func = Nikto,
    ),
    Tool(
        name="NmapScanner",
        description="NmapScanner is a scanner that looks for vulnerabilites given an application or an website domain or its ip address",
        func = Nmap_Scanner,
    ),
    Tool(
        name="Shodan",
        description="Shodan is a directory enumeration tool looking for directories and virtual hosts",
        func = Shodan,
    ),
    Tool(
        name="Spiderfoot",
        description="Spiderfoot is a directory enumeration tool looking for directories and virtual hosts",
        func = Spiderfoot,
    )
]


import logging