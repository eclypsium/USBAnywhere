import click
import hexdump
import socket
import struct

from Cryptodome.Cipher import ARC4

class BasedIntParamType(click.ParamType):
    name = 'integer'

    def convert(self, value, param, ctx):
        try:
            if value[:2].lower() == '0x':
                return int(value[2:], 16)
            elif value[:1] == '0':
                return int(value, 8)
            return int(value, 10)
        except ValueError:
            self.fail('%s is not a valid integer' % value, param, ctx)


BASED_INT = BasedIntParamType()


def send_request(conn, op, payload):
    return conn.send(struct.pack('<II', op, len(payload)) + bytes(payload))


def recv_response(conn):
    header = conn.recv(8)
    (op, payload_len) = struct.unpack_from('<II', header)
    if not payload_len:
        return (op, None)

    payload = conn.recv(payload_len)
    return (op, payload)


@click.group()
def cli():
    pass


@cli.command()
@click.option('-p', '--port', type=click.IntRange(1, 65535), default=623)
@click.argument('host')
@click.argument('op', type=BASED_INT)
@click.argument('payload', type=BASED_INT, nargs=-1)
def raw(host, port, op, payload):
    conn = socket.create_connection((host, port))

    print('Request op: 0x{:x}\nPayload:'.format(op))
    hexdump.hexdump(bytes(payload))
    print('')

    send_request(conn, op, bytes(payload))

    (op, payload) = recv_response(conn)

    print('Response op: 0x{:x}\nPayload:'.format(op))
    hexdump.hexdump(payload)


@cli.command()
@click.option('-p', '--port', type=click.IntRange(1, 65535), default=623)
@click.argument('host')
def status(host, port):
    conn = socket.create_connection((host, port))

    send_request(conn, 0x8000000, bytes())

    (op, payload) = recv_response(conn)

    print('Response op: 0x{:x}\nPayload:'.format(op))
    hexdump.hexdump(payload)


@cli.command()
@click.option('-p', '--port', type=click.IntRange(1, 65535), default=623)
@click.argument('host')
def get_http_port(host, port):
    conn = socket.create_connection((host, port))

    send_request(conn, 0xa000000, bytes())

    (op, payload) = recv_response(conn)
    if op != 0xb000000 or not payload:
        print('Unexpected response: opcode=0x{:x} payload={}'.format(
            op, repr(payload)))
        return

    (http_port, ) = struct.unpack('<H', payload)
    print('Response op: 0x{:x}\nHTTP port: {}'.format(op, http_port))


@cli.command()
@click.option('-k', '--key', default='BX80570E3110Q814A447')
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
def rc4(key, infile, outfile):
    cipher = ARC4.new(bytes(key, 'ascii'))
    outfile.write(cipher.encrypt(infile.read()))