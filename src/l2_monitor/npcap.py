"""Read-only Npcap capture and the Ethernet/PPPoE IPv4/TCP subset we use."""
import collections
import ctypes as c
import os
import socket
import struct
import threading
import time
from pathlib import Path


class Device(c.Structure):
    pass


Device._fields_ = [('next',c.POINTER(Device)),('name',c.c_char_p),('description',c.c_char_p),
                  ('addresses',c.c_void_p),('flags',c.c_uint32)]


class Header(c.Structure):
    _fields_ = [('seconds',c.c_int32),('microseconds',c.c_int32),
                ('caplen',c.c_uint32),('length',c.c_uint32)]


class Bpf(c.Structure):
    _fields_ = [('length',c.c_uint32),('instructions',c.c_void_p)]


_library = None
_library_lock = threading.Lock()


def library():
    global _library
    with _library_lock:
        if _library is not None:
            return _library
        path = Path(os.environ.get('SystemRoot','C:/Windows')) / 'System32/Npcap/wpcap.dll'
        if not path.exists():
            raise OSError('Npcap не установлен: не найден System32/Npcap/wpcap.dll')
        p = c.CDLL(str(path))
        signatures = {
            'pcap_findalldevs':([c.POINTER(c.POINTER(Device)),c.c_char_p],c.c_int),
            'pcap_freealldevs':([c.POINTER(Device)],None),
            'pcap_open_live':([c.c_char_p,c.c_int,c.c_int,c.c_int,c.c_char_p],c.c_void_p),
            'pcap_compile':([c.c_void_p,c.POINTER(Bpf),c.c_char_p,c.c_int,c.c_uint32],c.c_int),
            'pcap_setfilter':([c.c_void_p,c.POINTER(Bpf)],c.c_int),
            'pcap_freecode':([c.POINTER(Bpf)],None),
            'pcap_setnonblock':([c.c_void_p,c.c_int,c.c_char_p],c.c_int),
            'pcap_next_ex':([c.c_void_p,c.POINTER(c.POINTER(Header)),c.POINTER(c.POINTER(c.c_ubyte))],c.c_int),
            'pcap_geterr':([c.c_void_p],c.c_char_p),
            'pcap_datalink':([c.c_void_p],c.c_int),
            'pcap_close':([c.c_void_p],None),
        }
        for name,(args,result) in signatures.items():
            function=getattr(p,name);function.argtypes=args;function.restype=result
        _library=p
        return p


def interfaces():
    p,head,error=library(),c.POINTER(Device)(),c.create_string_buffer(512)
    if p.pcap_findalldevs(c.byref(head),error):
        raise OSError(error.value.decode('utf-8','replace'))
    result=[]
    try:
        current=head
        while current:
            entry=current.contents
            device=entry.name.decode('utf-8','replace')
            name=(entry.description or entry.name).decode('utf-8','replace')
            result.append(dict(id=str(len(result)+1),device=device,name=name,recommended=False))
            current=entry.next
    finally:
        p.pcap_freealldevs(head)
    return result


def packet_row(data, link_type, timestamp, frame):
    """No inferred bytes: truncated, fragmented or unsupported IP is omitted."""
    if link_type == 1:
        if len(data)<14:return None
        protocol,offset=int.from_bytes(data[12:14],'big'),14
        while protocol in (0x8100,0x88a8,0x9100):
            if len(data)<offset+4:return None
            protocol,offset=int.from_bytes(data[offset+2:offset+4],'big'),offset+4
        if protocol == 0x8864:
            if len(data)<offset+8 or data[offset+1]!=0:return None
            declared=int.from_bytes(data[offset+4:offset+6],'big')
            if declared<2 or len(data)<offset+6+declared:return None
            if data[offset+6:offset+8]!=b'\x00\x21':return None
            offset+=8
        elif protocol != 0x0800:
            return None
    elif link_type in (101,228):
        offset=0
    elif link_type == 0:
        if len(data)<4 or data[:4] not in (b'\x02\0\0\0',b'\0\0\0\x02'):return None
        offset=4
    else:
        return None
    if len(data)<offset+20 or data[offset]>>4!=4 or data[offset+9]!=6:return None
    ihl=(data[offset]&15)*4
    total=int.from_bytes(data[offset+2:offset+4],'big')
    fragment=int.from_bytes(data[offset+6:offset+8],'big')
    if ihl<20 or fragment&0x3fff or total<ihl+20 or len(data)<offset+total:return None
    tcp=offset+ihl
    tcp_size=(data[tcp+12]>>4)*4
    if tcp_size<20 or ihl+tcp_size>total:return None
    source_port,destination_port,seq=struct.unpack_from('!HHI',data,tcp)
    return {'frame.number':str(frame),'frame.time_epoch':timestamp,
            'ip.src':socket.inet_ntoa(data[offset+12:offset+16]),'ip.dst':socket.inet_ntoa(data[offset+16:offset+20]),
            'tcp.srcport':str(source_port),'tcp.dstport':str(destination_port),'tcp.stream':'0',
            'tcp.seq_raw':str(seq),'tcp.flags.syn':'1' if data[tcp+13]&2 else '0',
            'tcp.payload':data[tcp+tcp_size:offset+total].hex()}


class Capture:
    """Same engine contract as TShark Capture, without an external process."""
    def __init__(self,endpoint,interface,run_dir):
        self.endpoint=endpoint
        self.lock=threading.Lock()
        self.rows=collections.deque(maxlen=30000)
        self.diagnostics=collections.deque(maxlen=15)
        self.received=0
        self.process=self
        self.closed=threading.Event()
        self.error=None
        self.p=library()
        error=c.create_string_buffer(512)
        self.handle=self.p.pcap_open_live(interface['device'].encode(),65535,0,50,error)
        if not self.handle:raise OSError(error.value.decode('utf-8','replace'))
        self.file=None
        try:
            self.link_type=self.p.pcap_datalink(self.handle)
            if self.link_type not in (0,1,101,228):
                raise ValueError(f'Неподдерживаемый тип интерфейса Npcap: {self.link_type}')
            host,port=endpoint['remote_ip'],endpoint['remote_port']
            expression=f'(host {host} and tcp port {port}) or (pppoes and host {host} and tcp port {port})'
            program=Bpf()
            if self.p.pcap_compile(self.handle,c.byref(program),expression.encode(),1,0xffffffff):
                raise OSError(self.p.pcap_geterr(self.handle).decode('utf-8','replace'))
            try:
                if self.p.pcap_setfilter(self.handle,c.byref(program)):
                    raise OSError(self.p.pcap_geterr(self.handle).decode('utf-8','replace'))
            finally:self.p.pcap_freecode(c.byref(program))
            if self.p.pcap_setnonblock(self.handle,1,error):
                raise OSError(error.value.decode('utf-8','replace'))
            self.run_dir=Path(run_dir)
            self.rotation=-1
            self._rotate()
            self.thread=threading.Thread(target=self._read,daemon=True,name='Npcap capture')
            self.thread.start()
        except Exception:
            if self.file:self.file.close()
            self.p.pcap_close(self.handle);self.handle=None
            raise

    def _rotate(self):
        if self.file:self.file.close()
        self.rotation+=1
        self.file=(self.run_dir/f'capture-{self.rotation%2}.pcap').open('wb')
        self.file.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,self.link_type))
        self.rotation_time=time.monotonic()
        self.flush_time=self.rotation_time

    def _read(self):
        header,data=c.POINTER(Header)(),c.POINTER(c.c_ubyte)()
        try:
            while not self.closed.is_set():
                outcome=self.p.pcap_next_ex(self.handle,c.byref(header),c.byref(data))
                if outcome==0:
                    self.closed.wait(0.01)
                    continue
                if outcome<0:
                    raise OSError(self.p.pcap_geterr(self.handle).decode('utf-8','replace'))
                h=header.contents
                if h.caplen>65535:raise ValueError('Npcap превысил snaplen')
                raw=c.string_at(data,h.caplen)
                now=time.monotonic()
                if now-self.rotation_time>=60 or self.file.tell()+h.caplen+16>4*1024*1024:self._rotate()
                self.file.write(struct.pack('<IIII',h.seconds,h.microseconds,h.caplen,h.length)+raw)
                if now-self.flush_time>=1:self.file.flush();self.flush_time=now
                row=packet_row(raw,self.link_type,f'{h.seconds}.{h.microseconds:06d}',self.received+1)
                if not row:continue
                e=self.endpoint
                forward=(row['ip.src']==e['local_ip'] and row['tcp.srcport']==str(e['local_port']) and
                         row['ip.dst']==e['remote_ip'] and row['tcp.dstport']==str(e['remote_port']))
                reverse=(row['ip.dst']==e['local_ip'] and row['tcp.dstport']==str(e['local_port']) and
                         row['ip.src']==e['remote_ip'] and row['tcp.srcport']==str(e['remote_port']))
                if not (forward or reverse):continue
                with self.lock:
                    self.received+=1
                    self.rows.append(row)
        except Exception as error:
            self.error=str(error);self.diagnostics.append(self.error)
        finally:
            if self.file:self.file.close();self.file=None

    def poll(self):
        return None if self.thread.is_alive() else 1 if self.error else 0

    def read_rows(self):
        with self.lock:return list(self.rows)

    def trim(self,timestamp_ns):
        cutoff=timestamp_ns/1e9-3
        with self.lock:
            while self.rows and float(self.rows[0]['frame.time_epoch'])<cutoff:self.rows.popleft()

    def close(self):
        self.closed.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError('Поток Npcap ещё завершается; дескриптор сохранён')
        if self.handle:self.p.pcap_close(self.handle);self.handle=None
