from IPython.display import HTML, display

def hint_message(message):
    display(HTML(f"""
    <div style="background-color: #d1e7dd; border-left: 5px solid #0f5132; padding: 10px;">
        <strong>Hint:</strong> {message}
    </div>
    """))

def warning_message(message):
    display(HTML(f"""
    <div style="background-color: #f8d7da; border-left: 5px solid #842029; padding: 10px;">
        <strong>Warning:</strong> {message}
    </div>
    """))

def note_message(message, title="Note"):
    display(HTML(f"""
    <div style="background-color: #ADD8E6; border-left: 5px solid #000F81; padding: 10px;">
        <strong>{title}:</strong><br>
        <p>{message}</p>
    </div>
    """))
    
def info_explanation():
    explanation_text = """
    The explanation of inferred data (or a derivation) consists of five elements:

    <ul>
    <li><strong>Data inferred for query statement Q:</strong> the statement in the query that triggered the application of an inference rule</li>
    <li><strong>Applied rule:</strong> the inference rule that was applied</li>
    <li><strong>Condition met:</strong> shows how the rule's conditions are satisfied by data in the CTI SKB.</li>
    <li><strong>Inferred conclusion:</strong> is the result of the application of the rule.</li>
    <li><strong>Mapping of variables:</strong> shows how the variables in the query statement Q map to the variables of the rule applied.</li>
    </ul>
    """
    note_message(explanation_text, "Interpreting an explanation")
