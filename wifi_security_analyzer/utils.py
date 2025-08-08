import subprocess

def run_command(command, capture_output=True):
    """Execute shell command and return output or error as a string."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=capture_output,
            text=True,
            check=True
        )
        return result.stdout if capture_output else ""
    except subprocess.CalledProcessError as e:
        error_msg = f"Command '{command}' failed: {e.stderr if capture_output else 'Unknown error'}"
        return error_msg
    except Exception as e:
        error_msg = f"Error executing command '{command}': {str(e)}"
        return error_msg