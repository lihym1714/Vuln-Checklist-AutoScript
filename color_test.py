for i in range(1,100):
    color = "\033["+str(i)+"m"
    RESET = "\033[0m"
    print(f"{color}color test: {i}m{RESET}")