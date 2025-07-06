class Colors:
    # ANSI color codes
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def red(text):
    return f"{Colors.RED}{text}{Colors.RESET}"

def green(text):
    return f"{Colors.GREEN}{text}{Colors.RESET}"

def yellow(text):
    return f"{Colors.YELLOW}{text}{Colors.RESET}"

def blue(text):
    return f"{Colors.BLUE}{text}{Colors.RESET}"

def magenta(text):
    return f"{Colors.MAGENTA}{text}{Colors.RESET}"

def cyan(text):
    return f"{Colors.CYAN}{text}{Colors.RESET}"

def bold(text):
    return f"{Colors.BOLD}{text}{Colors.RESET}"

def success(text):
    return f"{Colors.GREEN}[+]{Colors.RESET} {text}"

def error(text):
    return f"{Colors.RED}[!]{Colors.RESET} {text}"

def info(text):
    return f"{Colors.BLUE}[*]{Colors.RESET} {text}"

def warning(text):
    return f"{Colors.YELLOW}[!]{Colors.RESET} {text}"

def progress(text):
    return f"{Colors.CYAN}[>]{Colors.RESET} {text}"

def negative(text):
    return f"{Colors.YELLOW}[-]{Colors.RESET} {text}"