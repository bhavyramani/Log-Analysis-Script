# Funtion to convert String line input to Readable Dictionary
def parse_input(line):  
    line = line.strip()
    line = line.strip('\n')
    line = line.split(' ')
    
    data = dict()

    data['ip'] = line[0]
    data['datetime'] = line[3] + ' ' + line[4]
    data['request_type'] = line[5].strip('"')

    data['endpoint'] = line[6]
    data['protocol'] = line[7].strip('"')
    data['status_code'] = line[8]
    data['response_size'] = line[9]
    
    if len(line) > 10:
        data['message'] = line[10]
        
    return data


# Function to write output to file and console
def write_output(data, pad_size = -1):
    # Padding data with spaces or print new line
    if pad_size == -1:
        data = data + '\n'
    else:
        data = data.ljust(pad_size)
    output_file.write(data)
    print(data, end = '')
    
    
ip_count = dict()              # Dictionary to store IP count
end_point_count = dict()       # Dictionary to store Endpoint count
brute_force_attepmts = dict()  # Dictionary to store Brute Force Attempts
brute_force_threshold = 10     # Threshold to for Brute Force Detection (default : 10)


# Process input data
def process_count(data):
    # Using global variables inside function
    global ip_count, most_freq_ap, brute_force_attepmts
    
    # Logic to conut IP address
    if data['ip'] in ip_count:
        ip_count[data['ip']] += 1
    else:
        ip_count[data['ip']] = 1
        
    # Logic to store count of each endpoint
    if data['endpoint'] in end_point_count:
        end_point_count[data['endpoint']] += 1
    else:
        end_point_count[data['endpoint']] = 1
    
    # Logic to detect Brute Force Attempts
    if data['status_code'] == '401' or ('message' in data and data['message'] == 'Invalid credentials'):
        if data['ip'] in brute_force_attepmts:
            brute_force_attepmts[data['ip']] += 1
        else:
            brute_force_attepmts[data['ip']] = 1
            
            
# Function to print IP counts as per output format
def print_ip_count():
    pad_size = 20
    
    # Sort IP addresses based on descending order of count
    ip_count_list = []
    for ip, count in ip_count.items():
        ip_count_list.append((ip, count))
    ip_count_list = sorted(ip_count_list, key=lambda x: x[1], reverse=True)
    
    write_output('IP Address,', pad_size)
    write_output('Request Count')
    
    for ip, count in ip_count_list:
        write_output(ip + ',', pad_size)
        write_output(str(count))

    write_output('\n') # Seperator for next output
    

# Function to print most frequent endpoint as per output format
def print_most_frequent_endpoint():
    # Initialize max count of an endpoint with 0
    max_count = 0
    # To store most frequent endpoint
    most_freq_endpoint = ''
    
    # Find most frequent endpoint
    for endpoint, count in end_point_count.items():
        if count > max_count:
            max_count = count
            most_freq_endpoint = endpoint
            
    pad_size = len(most_freq_endpoint) + 10

    write_output('Endpoint,', pad_size)
    write_output('Access Count')
    
    write_output(most_freq_endpoint + ',', pad_size)
    write_output(str(max_count))
    
    write_output('\n') # Seperator for next output
    

# Function to print Brute Force Attempts as per output format
def print_brute_force_attempts():
    pad_size = 20
    
    write_output('IP Address,', pad_size)
    write_output('Failed Login Count')
    
    for ip, count in brute_force_attepmts.items():
        # Mark as brute force attempt if count is greater than threshold
        if count >= brute_force_threshold:
            write_output(ip + ',', pad_size)
            write_output(str(count))
    

if __name__ == '__main__':
    global output_file
    output_file = open('log_analysis_results.csv', 'w')
    
    # Read input file line by line so it can handle large files
    with open('sample.log') as f:   
        lines = f.readlines()        
        for line in lines:
            # Parsing the input line to dictionary
            data = parse_input(line)
            
            # Process data of current line
            process_count(data)
            
        # Calling main functionalities
        print_ip_count()
        print_most_frequent_endpoint()
        print_brute_force_attempts()
    
    output_file.close()