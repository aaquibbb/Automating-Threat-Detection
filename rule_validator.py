import yara

def validate_rule(rule_path):
    try:
        yara.compile(filepath=rule_path)
        print("SYNTAX VALID: Rule compiled successfully")
        return True
    except yara.SyntaxError as e:
        print("SYNTAX ERROR:", e)
        return False

if __name__ == "__main__":
    validate_rule("./eval_shell.yar")
