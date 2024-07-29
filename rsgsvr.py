import argparse
import locale
import socket
import select
import struct
import enum
import time
import zlib
import threading
import ipaddress
from asyncio import IncompleteReadError
from socketserver import BaseRequestHandler, StreamRequestHandler, ThreadingTCPServer
from typing import Dict, Optional, Tuple, Union


class SocketIO(socket.socket):
    def __init__(
        self,
        sock: socket.socket,
        timeout: int
    ) -> None:
        self.__sock = sock
        self.__timeout = timeout
    
    @property
    def socket(
        self
    ) -> socket.socket:
        return self.__sock
    
    def read(
        self,
        size: int
    ) -> bytes:
        s = self.__sock
        r, _, _ = select.select([s], [], [], self.__timeout)
        if s not in r:
            raise RuntimeError('timed out - read')
        return s.recv(size)
    
    def read_all(
        self,
        size: int
    ) -> bytes:
        """
        Receive exactly bufsize bytes from the socket.

        :param size: The number of length to read.
        :return: The data read.
        """
        s = self.__sock
        buf = bytearray(size)
        view = memoryview(buf)
        pos = 0
        while pos < size:
            r, _, _ = select.select([s], [], [], self.__timeout)
            if s not in r:
                raise RuntimeError('timed out - read')

            n = s.recv_into(view[pos:])
            if not n:
                raise IncompleteReadError(buf, size)
            pos += n
        return bytes(buf)
    
    def read_struct(
        self,
        fmt: str
    ) -> tuple:
        """
        Read and unpack a structured payload

        :param fmt: The format string of the structure.
        :return: The structure unpacked.
        """
        st = struct.Struct(fmt)
        return st.unpack(self.read_all(st.size))

    def read_payload(
        self
    ) -> bytes:
        """
        Read and unpack a sized payload

        :return: The payload.
        """
        payload_size, = self.read_struct('!I')
        return self.read_all(payload_size)

    def write(
        self,
        data: bytes
    ) -> int:
        s = self.__sock
        _, w, _ = select.select([], [s], [], self.__timeout)
        if s not in w:
            raise RuntimeError('timed out - write')

        return s.send(data)
    
    def write_all(
        self,
        data: bytes
    ) -> int:
        s = self.__sock
        total = 0
        while total < len(data):
            _, w, _ = select.select([], [s], [], self.__timeout)
            if s not in w:
                raise RuntimeError('timed out - write')

            n = s.send(data[total:])
            if n == 0:
                raise RuntimeError('connection broken')
            total += n
        return total

    def wait_for_read(
        self
    ) -> bool:
        r, _, _ = select.select([self.__sock], [], [], self.__timeout)
        return self.__sock in r


class ServerSockets:
    def __init__(
        self
    ) -> None:
        self.__mutex = threading.Lock()
        self.__tcp_sockets: Dict[Tuple[str, int], socket.socket] = {}
        self.__udp_sockets: Dict[Tuple[str, int], socket.socket] = {}

    def __del__(
        self
    ) -> None:
        for s in self.__tcp_sockets.values():
            s.close()
        for s in self.__udp_sockets.values():
            s.close()

    def bind_tcp_socket(
        self,
        ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        port: int
    ) -> socket.socket:
        addr = (str(ip), port)
        with self.__mutex:
            s = self.__tcp_sockets.get(addr)
            if s is not None:
                return s

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(addr)
            except Exception as e:
                s.close()
                raise

            s.listen(5)
            self.__tcp_sockets[addr] = s
            return s

    def bind_udp_socket(
        self,
        ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        port: int
    ) -> socket.socket:
        addr = (str(ip), port)
        with self.__mutex:
            s = self.__udp_sockets.get(addr)
            if s is not None:
                return s

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind(addr)
            except Exception as e:
                s.close()
                raise

            self.__udp_sockets[addr] = s
            return s


class ManagementSessionHandler(StreamRequestHandler):
    """
    The management session handler
    """
    class SessionProtocol(enum.IntEnum):
        UDP = 0
        TCP = 1


    class ErrorStatus(enum.IntEnum):
        OK = 0
        NG = 1
    
    
    def __init__(
        self,
        request,
        client_address,
        server
    ) -> None:
        self.__sess: Optional[SocketIO] = None
        self.__timeout_udp_server = 3
        self.__timeout_tcp_accept = 3
        self.__timeout_tcp_session = 30
        self.__timeout_udp_session = 3
        self.__server_sockets = None
        super().__init__(request, client_address, server)


    def setup(
        self
    ) -> None:
        self.__server_sockets = self.server.server_sockets
        super().setup()


    def __build_ok_bind_response(
        self,
        sess_port: int
    ) -> bytes:
        """
        Build a OK response to a bind request

        :param status: The status code.
        :return: The OK response.
        """
        return struct.pack('!BH', self.ErrorStatus.OK, sess_port)

    def __build_ng_bind_response(
        self,
        message: str
    ) -> bytes:
        """
        Build a NG response to a bind request

        :param status: The status code.
        :param message: The status message.
        :return: The NG response.
        """
        message = message.encode('utf-8')
        payload = struct.pack('!BI', self.ErrorStatus.NG, len(message))
        return payload + message

    def __build_result(
        self,
        error_message: Optional[str]
    ) -> bytes:
        """
        Build an OK or NG response.
        This will build an OK response when error_message is None, otherwise build a NG response.

        :param error_message: The error message.
        :return: The response.
        """
        if error_message is None:
            return struct.pack('!B', self.ErrorStatus.OK)
        else:
            message = error_message.encode('utf-8')
            payload = struct.pack('!BI', self.ErrorStatus.NG, len(message))
            return payload + message

    def __handle_tcp(
        self,
        sess_port: int
    ) -> None:
        try:
            selfip, _ = self.__sess.socket.getsockname()
            ss = self.__server_sockets.bind_tcp_socket(
                ipaddress.ip_address(selfip),
                sess_port
            )
            self.__sess.write_all(self.__build_ok_bind_response(sess_port))
        except Exception as e:
            msg = f'Unable to bind the port {sess_port}'
            self.__sess.write_all(self.__build_ng_bind_response(msg))
            raise RuntimeError(f'{msg} - {str(e)}')

        r, _, _ = select.select([ss], [], [], self.__timeout_tcp_accept)
        if ss not in r:
            raise RuntimeError('timed out - accept')
        
        ms = SocketIO(self.__sess.socket, self.__timeout_tcp_session)
        cs, _ = ss.accept()
        with cs:
            dec = None
            while True:
                if not ms.wait_for_read():
                    raise RuntimeError('timed out - read')
                
                rwtype, = ms.read_struct('!B')
                if rwtype == 0:
                    if dec is not None:
                        plain = dec.flush()
                        if len(plain) != 0:
                            SocketIO(cs, self.__timeout_tcp_session).write_all(plain)
                    break
                elif rwtype == 1:
                    wlen, = ms.read_struct('!I')
                    while wlen > 0:
                        rlen = len(cs.recv(wlen))
                        if rlen == 0:
                            raise RuntimeError('Disconnected - tcp read')
                        wlen -= rlen
                
                elif rwtype == 2:
                    comp_data = ms.read_payload()
                    if len(comp_data) == 0:
                        if dec is None:
                            plain = b''
                        else:
                            plain = dec.flush()
                    else:
                        if dec is None:
                            dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        plain = dec.decompress(comp_data)
                    
                    if len(plain) != 0:
                        SocketIO(cs, self.__timeout_tcp_session).write_all(plain)
                    
                    if dec.eof:
                        dec = None

                else:
                    raise RuntimeError(f'Invalid R/W type - {rwtype}')

    def __handle_udp(
        self,
        sess_port: int
    ) -> None:
        try:
            selfip, _ = self.__sess.socket.getsockname()
            ss = self.__server_sockets.bind_udp_socket(
                ipaddress.ip_address(selfip),
                sess_port
            )
            self.__sess.write_all(self.__build_ok_bind_response(sess_port))
        except Exception as e:
            msg = f'Unable to bind the port {sess_port}'
            self.__sess.write_all(self.__build_ng_bind_response(msg))
            raise RuntimeError(f'{msg} - {str(e)}')

        ms = SocketIO(self.__sess.socket, self.__timeout_udp_session)
        peer = None
        while True:
            if not ms.wait_for_read():
                raise RuntimeError('timed out - read')
            
            if len(ms.socket.recv(1, socket.MSG_PEEK)) == 0:
                break
            
            rwtype, = ms.read_struct('!B')
            if rwtype == 0:
                return
            elif rwtype == 1:
                wlen, = ms.read_struct('!I')
                _, peer = ss.recvfrom(wlen)
            elif rwtype == 2:
                peer_ip = ms.read_payload().decode()
                peer_port, = ms.read_struct('!H')
                if peer is None:
                    peer = peer_ip, peer_port
                ss.sendto(ms.read_payload(), peer)
            else:
                raise RuntimeError(f'Invalid R/W type - {rwtype}')

    def handle(
        self
    ) -> None:
        while True:
            r, _, _ = select.select([self.request], [], [])
            if self.request not in r:
                continue
            try:
                if len(self.request.recv(1, socket.MSG_PEEK)) == 0:
                    break
            except ConnectionResetError:
                break
            
            # bind request
            self.__sess = SocketIO(self.request, self.__timeout_tcp_session)
            
            protocol_version, sess_protocol, sess_port = self.__sess.read_struct('!BBH')
            if protocol_version != 1:
                self.__sess.write_all(
                    self.__build_ng_bind_response(f'Unsupported protocol version: {protocol_version}')
                )
            elif sess_protocol == self.SessionProtocol.TCP:
                self.__handle_tcp(sess_port)
            elif sess_protocol == self.SessionProtocol.UDP:
                self.__handle_udp(sess_port)
            else:
                self.__sess.write_all(
                    self.__reply_ng_bind_response(f'Invalid protocol: {sess_protocol}')
                )


def parse_args(
) -> argparse.Namespace:
    """ Parse the argument parameters

    :return: The argument parameters parsed.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument(
        '--port',
        type=int,
        default=65534
    )
    return ap.parse_args()


def main(
) -> None:
    """
    Main
    """
    args = parse_args()

    locale.setlocale(locale.LC_ALL, 'C')

    # Run the server
    ThreadingTCPServer.allow_reuse_address = True
    ThreadingTCPServer.server_sockets = ServerSockets()
    with ThreadingTCPServer(('', args.port), ManagementSessionHandler) as svr:
        print(f'The RSG server is running on port {args.port}.')
        svr.serve_forever()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
