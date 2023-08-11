from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        ttl_ = ttl - 1
        if ttl_ == 0:
            datagramaICMP = self.createICMP(datagrama)
            self.enviar(datagramaICMP, src_addr, 0x01)
            return
        datagrama = self.change_ttl(datagrama, ttl_)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def createICMP(self, datagrama):
        # type = 11
        # code = 0
        byte0and1 = struct.pack("!BB", 0xb, 0x0)
        # checksum = 0
        byte2and3 = struct.pack("!H", 0)
        # unused = 0
        byte4to7 = struct.pack("!I", 0)
        rest = datagrama[:28]
        byte8to11 = rest
        payloadICMP = byte0and1 + byte2and3 + byte4to7 + byte8to11
        checksum = calc_checksum(payloadICMP)
        byte2and3 = struct.pack("!H", checksum)
        payloadICMP = byte0and1 + byte2and3 + byte4to7 + byte8to11
        return payloadICMP

    def change_ttl(self, datagrama, new_ttl):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        # version = 4
        # ihl = 5
        byte0 = struct.pack("!B", 0x45)

        byte1 = struct.pack("!B", dscp & ecn)

        totalLength = len(payload)
        byte2and3 = struct.pack("!H", totalLength)

        byte4and5 = struct.pack("!H", identification)

        byte6and7 = struct.pack("!H", flags & frag_offset)

        byte8 = struct.pack("!B", new_ttl)

        byte9 = struct.pack("!B", proto)

        # headerChecksum = 0
        byte10and11 = struct.pack("!H", 0x0000)

        sourceIpAddr, = struct.unpack('!I', str2addr(src_addr))
        byte12to15 = struct.pack("!I", sourceIpAddr)

        destIpAddr, = struct.unpack('!I', str2addr(dst_addr))
        byte16to19 = struct.pack("!I", destIpAddr)

        datagrama = byte0 + byte1 + byte2and3 + byte4and5 + byte6and7 + byte8 + byte9 + byte10and11 + byte12to15 + byte16to19
        headerChecksum = calc_checksum(datagrama)
        byte10and11 = struct.pack("!H", headerChecksum)
        datagrama = byte0 + byte1 + byte2and3 + byte4and5 + byte6and7 + byte8 + byte9 + byte10and11 + byte12to15 + byte16to19
        return datagrama

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        matching_routes = []  # Lista para armazenar rotas casadas

        for cidr, next_hop in self.tabela_encaminhamento:
            network_ip, prefix_len = cidr.split('/')
            if self._ip_in_network(dest_addr, network_ip, int(prefix_len)):
                matching_routes.append((int(prefix_len), next_hop))  # Alteração aqui
    
        if matching_routes:
            # Ordena as rotas casadas com base no prefixo mais longo (maior prefix_len)
            matching_routes.sort(reverse=True)
            return matching_routes[0][1]

    def _ip_in_network(self, ip, network_ip, prefix_len):
        """
        Verifica se o endereço IP está na rede especificada pelo CIDR.
        """
        ip_parts = ip.split('.')
        network_parts = network_ip.split('.')
        mask = (1 << 32) - (1 << (32 - prefix_len))
        
        ip_int = 0
        for part in ip_parts:
            ip_int = (ip_int << 8) + int(part)
        
        network_int = 0
        for part in network_parts:
            network_int = (network_int << 8) + int(part)
        
        return (ip_int & mask) == (network_int & mask)

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, proto = 0x06):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        src_addr = self.meu_endereco
        ttl = 64  # Defina o TTL conforme necessário

        # Monta o cabeçalho IP
        version_ihl = (4 << 4) | (5)  # Versão 4 (IPv4) e IHL (Internet Header Length) de 5 palavras de 32 bits
        dscp_ecn = 0  # Defina o DSCP (Differentiated Services Code Point) e ECN (Explicit Congestion Notification)
        total_len = 20 + len(segmento)  # Tamanho total do datagrama em bytes
        identification = 0  # Identificação do datagrama (pode ser deixado como 0)
        flags_fragoffset = 0  # Flags e offset de fragmentação (pode ser deixado como 0)
        #proto = IPPROTO_TCP  # Protocolo TCP
        checksum = 0  # O checksum será calculado posteriormente
        src_addr_parts = list(map(int, src_addr.split('.')))
        src_addr_packed = struct.pack('!BBBB', *src_addr_parts)
        dst_addr_parts = list(map(int, dest_addr.split('.')))
        dst_addr_packed = struct.pack('!BBBB', *dst_addr_parts)

        # Monta o cabeçalho IP completo
        ip_header = struct.pack('!BBHHHBBH', version_ihl, dscp_ecn, total_len, identification,
                                flags_fragoffset, ttl, proto, checksum)
        ip_header += src_addr_packed + dst_addr_packed

        # Calcula o checksum do cabeçalho IP
        checksum = calc_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]

        # Monta o datagrama completo
        datagram = ip_header + segmento

        # Envia o datagrama para o próximo salto
        self.enlace.enviar(datagram, next_hop)
