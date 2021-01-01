# Eric Miramontes
# 2/6/2019
# PA 1-Final Program: Multi-client Proxy with Malware Filter
import sys
from socket import *
import re
from time import gmtime, strftime
import threading
import hashlib
import json


# Proxy sends back html with appropriate error code describing an invalid request if one was sent
def invalid_request(error_code, error_name):
    print('Received invalid request {} ({})\n'.format(error_code, error_name))
    body = ('<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">'
            '<html><head>'
            '<title>' + str(error_code) + ' ' + error_name + '</title>'
            '</head><body>'
            '<h1>' + error_name + '</h1>' 
            '<p>Your browser sent a request that this proxy could not understand.<br />'
            '</p>'
            '</body></html>\n')
    length = str(len(body))
    message = ('HTTP/1.1 ' + str(error_code) + ' ' + error_name + '\r\n' +
               'Date: ' + strftime('%a, %d %b %Y %H:%M:%S GMT', gmtime()) + '\r\n' +
               'Server: CS4480-Proxy\r\n'
               'Content-Length: ' + length + '\r\n' +
               'Connection: close\r\n'
               'Content-Type: text/html; charset=iso-8859-1\r\n\r\n')
    return message + body


# Proxy sends back html warning client that they are trying to access malware.
def malware_response(md5_hash, pos_ids: int, total_ids: int, scan_date, name, permalink):
    body = ('<html><body>'
            '<h1>The File you requested appears to contain Malware</h2>' +
            '<h2>Information:</h2>'
            '<ul>'
            '<li>MD5 Hash: ' + md5_hash + '</li>'
            '<li>Positives: ' + str(pos_ids) + '/' + str(total_ids) + '</li>'
            '<li>Scan Date: ' + scan_date + '</li>' +
            '<li>First Scan ID: ' + name + '</li>' +
            '/ul'
            '<p>Thanks to VirusTotal for this information</p>'
            '<p>For more information see '
            '<a href="' + permalink + '">Virus Total Permanent Link</a></p>'
            '</body></html>\n')
    length = str(len(body))
    message = ('HTTP/1.1 200 OK\r\n'
               'Date: ' + strftime('%a, %d %b %Y %H:%M:%S GMT', gmtime()) + '\r\n' +
               'Server: CS4480-Proxy\r\n'
               'Content-Length: ' + length + '\r\n' +
               'Connection: close\r\n'
               'Content-Type: text/html; charset=iso-8859-1\r\n\r\n')
    return message + body


# When a new client connects, their request is parsed and sent to the desired webserver.
# The response is either altered if it is an html page or checked for malware.
def new_client(conn):
    with conn:
        # client request and server response byte messages
        request = b''
        response = b''
        virus_response = b''
        while True:
            client_data = conn.recv(1024)
            request += client_data
            if not client_data:
                break

            # process request
            if request.endswith(b'\r\n\r\n'):
                # parse http request, adding a close connection header.
                request_string = request.decode('utf-8', 'ignore').strip().\
                    replace('Connection: keep-alive', 'Connection: close').\
                    replace('Connection: Keep-Alive', 'Connection: Close')
                request_header_lines = request_string.split('\r\n')
                status_line = request_header_lines[0].split(' ')

                # delete status line from list of request headers, that will be handled separately.
                del request_header_lines[0]

                # some programs, like Putty, send their own bytes before the actual message, delete them
                if len(status_line) > 3:
                    del status_line[0:len(status_line) - 3]

                # check if header lines are properly formatted
                are_headers_formatted = True
                for header in request_header_lines:
                    if not(re.match('^[a-zA-Z-]+: .+$', header)):
                        are_headers_formatted = False
                        break

                # If client sent a GET message
                if len(status_line) == 3 and re.search('GET$', status_line[0]) \
                        and re.match('^(http://|/).+', status_line[1]) \
                        and re.match('^HTTP/[0-9][.][0-9]$', status_line[2]) \
                        and are_headers_formatted:
                    # sometimes the client puts bytes at the beginning of the request, they need to be filtered out.
                    status_line[0] = 'GET'

                    # retrieve website hostname
                    # if client sent request in absolute URI form
                    if re.match('^http://.+', status_line[1]):
                        url = status_line[1][7:]
                        hostname = url.split('/')[0]

                        # put in host header line if one doesn't exist (ignore it if it does)
                        host_provided = False
                        for i, a in enumerate(request_header_lines):
                            if re.match('^Host: .+', a):
                                host_provided = True
                                break
                        if not host_provided:
                            request_header_lines.insert(0, 'Host: ' + hostname)
                    # if client sent request in relative URI form
                    else:
                        host_provided = False
                        for i, a in enumerate(request_header_lines):
                            if re.match('^Host: .+', a):
                                host_provided = True
                                hostname = request_header_lines[i].split()[1]
                                break
                        if not host_provided:
                            print('Host not provided.')
                            conn.sendall(invalid_request(400, 'Bad Request').encode())
                            break

                    # modify compression request
                    for i, a in enumerate(request_header_lines):
                        if re.match('^Accept-Encoding: .+$', a):
                            request_header_lines[i] = 'Accept-Encoding: none'

                    # put it all back together
                    modified_request_string = ' '.join(status_line) + '\r\n' + \
                                              '\r\n'.join(request_header_lines) + '\r\n\r\n'
                    print("\nModified request:\n", modified_request_string)

                    global server_port
                    # extract non standard port number from hostname if one was provided
                    hostname_list = hostname.split(':')
                    if re.search('(:[0-9]+)$', hostname):
                        server_port = int(hostname_list[1])
                        if len(hostname_list) > 2:
                            conn.sendall(invalid_request(400, 'Bad Request').encode())
                    else:
                        # otherwise, the default port is 80
                        server_port = 80
                    hostname = hostname_list[0]

                    # ss is the server socket for the site the client wants to access
                    with socket(AF_INET, SOCK_STREAM) as ss:
                        try:
                            # send the modified request on to the desired web server
                            print('Connecting to {} at port {}\n'.format(hostname, server_port))
                            ss.connect((gethostbyname(hostname), server_port))
                            ss.sendall(modified_request_string.encode())
                            while True:
                                server_data = ss.recv(1024)
                                response += server_data
                                if not server_data:
                                    break
                        except:
                            # return 400 message if connection failed
                            conn.sendall(invalid_request(400, 'Bad Request').encode())
                            break

                    # parse response
                    print('Received response:\n', response)
                    response_list = response.split(b'\r\n\r\n', 1)
                    response_header_lines = response_list[0].split(b'\r\n')

                    # if html was returned, replace all instances of "simple" with "silly" (keep capitalization)
                    if re.search(b'\r\nContent-Type: text/html', response_list[0]):
                        print('Modifying Response...')
                        response_list[1] = response_list[1].replace(b'Simple', b'Silly')
                        response_list[1] = response_list[1].replace(b'simple', b'silly')

                        # since the word simple is longer than silly, the content-length header needs to be updated
                        for i, response_header in enumerate(response_header_lines):
                            if re.match(b'^Content-Length: [1-9]+', response_header):
                                response_header_lines[i] = b'Content-Length: ' + str(len(response_list[1])).encode()
                                response_list[0] = b'\r\n'.join(response_header_lines)
                                break

                        # put it all back together and send it back to client
                        modified_response = b'\r\n\r\n'.join(response_list)
                        conn.sendall(modified_response)
                    # if it was anything else, such as a file, check it for malware.
                    else:
                        # VirusTotal key
                        key = sys.argv[2]

                        # check if "CS4480" is at the beginning of the message body and remove it
                        if response_list[1][0:6] == b'CS4480':
                            response_list[1] = response_list[1][6:]
                        checksum = hashlib.md5(response_list[1]).hexdigest()
                        print("\nQuerying VirusTotal for this resource hash: ", checksum)

                        virus_total_request = 'GET /vtapi/v2/file/report?apikey={apikey}&resource={resource} ' \
                                              'HTTP/1.1\r\n' \
                                              'Host: www.virustotal.com\r\n' \
                                              'Connection: close' \
                                              '\r\n\r\n'.format(apikey=key, resource=checksum)

                        # vss is the VirusTotal server socket
                        with socket(AF_INET, SOCK_STREAM) as vss:
                            try:
                                print('Connecting to VirusTotal')
                                vss.connect((gethostbyname('www.virustotal.com'), 80))
                                vss.sendall(virus_total_request.encode())
                                while True:
                                    virus_data = vss.recv(1024)
                                    virus_response += virus_data
                                    if not virus_data:
                                        break
                            except:
                                # Failsafe: if for whatever reason, the proxy couldn't connect to VirusTotal, just send
                                # back the file to the client without checking it.
                                conn.sendall(response)
                                break

                            # parse report and send back the appropriate response to the client
                            report = json.loads(virus_response.split(b'\r\n\r\n', 1)[1].decode())
                            print('Received VirusTotal report.')
                            if report['response_code'] == 1 and report['positives'] > 0:
                                print('Malware detected in the file!\n')
                                conn.sendall(
                                    malware_response(checksum, report['positives'], report['total'],
                                                     report['scan_date'], list(report['scans'])[0],
                                                     report['permalink']).encode())
                            else:
                                print('File is safe.\n')
                                conn.sendall(response)
                    print('Response sent\n\n\n')
                # if client sent a message other than GET
                elif len(status_line) == 3 and re.search('(POST|HEAD|PUT|DELETE)$', status_line[0]) \
                        and re.match('^(http://|/).+', status_line[1]) \
                        and re.match('^HTTP/[0-9][.][0-9]$', status_line[2])\
                        and are_headers_formatted:
                    conn.sendall(invalid_request(501, 'Not Implemented').encode())
                # if client sent a malformed message
                else:
                    conn.sendall(invalid_request(400, 'Bad Request').encode())
                break


# main method
def main():
    host = '127.0.0.1'
    # port = 65432  # for use with pycharm
    # listening port provided by user
    port = int(sys.argv[1])

    # cs is the client socket
    with socket(AF_INET, SOCK_STREAM) as cs:
        cs.bind((host, port))
        cs.listen()
        print('Proxy server is listening')

        # Accept connection from client and give them their own thread.
        while True:
            conn, addr = cs.accept()
            print('Connected by', addr)

            # proxy creates a new thread for each client
            threading.Thread(target=new_client, args=(conn,)).start()


if __name__ == "__main__":
    main()
