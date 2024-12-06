def parse_input(line):
    line = line.strip()
    line = line.strip('\n')
    line = line.split(' ')
    
    data = dict()

    data['ip'] = line[0]
    data['datetime'] = line[3] + ' ' + line[4]
    data['request_type'] = line[5].strip('"')

    data['url'] = line[6]
    data['protocol'] = line[7].strip('"')
    data['status_code'] = line[8]
    data['response_size'] = line[9]
    
    if len(line) > 10:
        data['message'] = line[10]
        
    return data

if __name__ == '__main__':
    with open('sample.log') as f:
        lines = f.readlines()
        
        all_data = []
        
        for line in lines:
            parsed_line = parse_input(line)
            all_data.append(parsed_line)
        
        print(all_data)