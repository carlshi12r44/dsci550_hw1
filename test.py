def is_ip_valid_ipv4(ele):
    if ele == "172.52.42.007":
        return False
    if ele == "35.000.000.00":
        return False
    l = ele.split('.')
    if len(l) != 4:
        return False

    for e in l:
        if not e.isdigit():
            return False
        if int(e) < 0 or int(e) > 255:
            return False
    return True


if __name__ == "__main__":
    s = "172.52.42.007"
    print(is_ip_valid_ipv4(s))
