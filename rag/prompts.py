from langchain_core.prompts import ChatPromptTemplate, FewShotChatMessagePromptTemplate

_EXAMPLES = [
    {
        "question": "Which IPs had the most blocked connections?",
        "answer": (
            "IP 192.168.1.105 had the most blocked connections with 12 events, "
            "followed by 10.0.0.55 with 8 blocks. Most were triggered by port scan "
            "detection on TCP port 443."
        ),
    },
    {
        "question": "Were there any critical severity events in the logs?",
        "answer": (
            "Yes, 3 critical events were found: two SQL injection attempts from "
            "203.0.113.42 and one DDoS pattern from 198.51.100.7, all blocked by "
            "the firewall."
        ),
    },
]

_example_prompt = ChatPromptTemplate.from_messages(
    [("human", "{question}"), ("ai", "{answer}")]
)

_few_shot = FewShotChatMessagePromptTemplate(
    example_prompt=_example_prompt,
    examples=_EXAMPLES,
)

_SYSTEM = (
    "You are a network security analyst assistant. "
    "Analyze the provided firewall logs and answer the question concisely in 2-4 sentences. "
    "Reference specific IPs, protocols, or patterns you observe. "
    "Only use information present in the logs below.\n\n"
    "Firewall logs:\n{context}"
)


def get_prompt() -> ChatPromptTemplate:
    return ChatPromptTemplate.from_messages(
        [("system", _SYSTEM), _few_shot, ("human", "{question}")]
    )
