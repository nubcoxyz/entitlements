"""
Use OpenAI to generate descriptions for entitlements.

Must set OPENAI_API_KEY in your environment.
    % export OPENAI_API_KEY=...
"""

import sqlite3

import openai

prompt = """You are an Apple macOS security expert learnt from apple documentation and security researchers.
For com.apple.security.hypervisor, you might say, this entitlement allows apps to create and manage virtual machines by giving access to the Hypervisor APIs. 
Please include the entitlement purpose and any security or privacy concerns. 
If you don't know please don't make up an answer.

What does the entitlement {} do?
"""

openai_errors = (openai.error.APIError, openai.error.Timeout, openai.error.APIConnectionError, openai.error.ServiceUnavailableError)
my_openai_errors = (openai.error.AuthenticationError, openai.error.InvalidRequestError, openai.error.RateLimitError)

class OpenAIError(Exception):
    pass

def get_answer(entitlement):
    try:
        response = openai.Completion.create(
            model='text-davinci-003', # 'text-curie-001', #
            prompt=prompt.format(entitlement),
            temperature=0.0,
            max_tokens=300,
            top_p=1.0,
            frequency_penalty=0.0,
            presence_penalty=0.0)
    except openai_errors as e:
        print(e)
        raise OpenAIError('Error from OpenAI')
    except my_openai_errors as e:
        print(e)
        raise OpenAIError('Error from OpenAI - mine')

    if response is None or response.choices is None or len(response.choices) == 0:
        raise OpenAIError('Error from OpenAI')
    return response.choices[0].text

def pull_entitlements_from_db(db_path):
    try:
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS descriptions (entitlement TEXT PRIMARY KEY, description TEXT)')
            c.execute('SELECT DISTINCT entitlement FROM entitlements LIMIT 50')
            for entitlement in c.fetchall():
                try:
                    answer = get_answer(entitlement[0])
                except OpenAIError as e:
                    print(e)
                    continue
                sys.stdout.write('.')
                # print(entitlement[0])
                # print(answer)
                c.execute('INSERT OR IGNORE INTO descriptions (entitlement, description) VALUES (?, ?)', (entitlement[0], answer))
                conn.commit()
    except sqlite3.Error as e:
        print(e)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print('Usage: python3 desc.py <entitlement>')
        print('Usage: python3 desc.py <db_path>')
        sys.exit(1)

    if sys.argv[1].endswith('.sqlite3'):
        pull_entitlements_from_db(sys.argv[1])
    else:
        try:
            answer = get_answer(sys.argv[1])
        except OpenAIError as e:
            print(e)
        else:
            print(answer)
