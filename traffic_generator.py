
#!/usr/bin/env python3

import argparse
import time
import random
import logging
from scapy.all import IP, UDP, TCP, ICMP, GRE, Raw, send

def generate_traffic(dest_ip, protocol, icmp_type, dest_port, pps, bps, log_file):
    """
    다양한 프로토콜(TCP, UDP, ICMP, GRE)을 사용해 트래픽을 생성하고 속도를 모니터링
    """
    # 로그 설정
    if log_file:
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
        logging.info(f"{protocol.upper()} 트래픽 생성 시작")
    
    # 패킷 크기 계산
    target_packet_size = (bps / pps) / 8  # 목표 패킷 크기 (bytes)

    interval = 1 / pps  # pps에 따른 전송 간격 계산
    total_packets = 0
    start_time = time.time()
    
    print(f"[INFO] {protocol.upper()} 트래픽 생성 시작: {pps} PPS, {bps} bps")
    print(f"[INFO] Destination Port: {dest_port}")
    try:
        while True:
            # 패킷 생성 시마다 랜덤 Source Port 설정
            src_port = random.randint(1, 65535)
            print(f"[DEBUG] Using Source Port: {src_port}")  # 디버그용 출력
            
            # 패킷 생성
            if protocol.upper() == "TCP":
                base_packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port)
            elif protocol.upper() == "UDP":
                base_packet = IP(dst=dest_ip) / UDP(sport=src_port, dport=dest_port)
            elif protocol.upper() == "ICMP":
                base_packet = IP(dst=dest_ip) / ICMP(type=icmp_type)
            elif protocol.upper() == "GRE":
                base_packet = IP(dst=dest_ip) / GRE()
            else:
                print(f"[ERROR] 지원하지 않는 프로토콜: {protocol}. TCP, UDP, ICMP, GRE 중 하나를 사용하세요.")
                return
            
            # 패킷 크기 조정
            payload_size = max(0, int(target_packet_size - len(base_packet)))  # 필요한 패딩 크기 계산
            packet = base_packet / Raw(load="X" * payload_size)  # 패딩 추가
            
            # 패킷 전송
            send(packet, verbose=False)
            total_packets += 1
            
            # 1초 간격으로 통계 출력 및 기록
            elapsed = time.time() - start_time
            if elapsed >= 1.0:
                print(f"[INFO] {total_packets} packets sent in last second")
                if log_file:
                    logging.info(f"{total_packets} packets sent in last second")
                total_packets = 0
                start_time = time.time()
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[INFO] 트래픽 생성 종료")
        if log_file:
            logging.info(f"{protocol.upper()} 트래픽 생성 종료")

def main():
    # 명령줄 인자 설정
    parser = argparse.ArgumentParser(description="다양한 프로토콜을 지원하는 트래픽 생성기")
    
    # 필수 인자
    parser.add_argument("dest_ip", help="목적지 IP 주소")
    
    # 선택 인자
    parser.add_argument("-t", "--protocol", type=str, default="UDP", help="프로토콜 형식 (TCP, UDP, ICMP, GRE)")
    parser.add_argument("-p", "--pps", type=int, default=1000, help="트래픽 pps 규모 (기본: 1Kpps)")
    parser.add_argument("-b", "--bps", type=int, default=100_000_000, help="트래픽 bps 규모 (기본: 100Mbps)")
    parser.add_argument("-d", "--dest-port", type=int, default=80, help="Destination Port (기본: 80, ICMP/GRE에서는 무시됨)")
    parser.add_argument("--icmp-type", type=int, default=8, help="ICMP 타입 (Echo Request: 8, Echo Reply: 0, 기본: 8)")
    parser.add_argument("--log-file", type=str, help="송신 속도를 기록할 로그 파일 경로")
    
    args = parser.parse_args()
    
    # 포트와 ICMP/GRE 예외 처리
    if args.protocol.upper() in ["ICMP", "GRE"]:
        args.dest_port = None
    
    # 트래픽 생성 함수 호출
    generate_traffic(
        dest_ip=args.dest_ip,
        protocol=args.protocol,
        icmp_type=args.icmp_type,
        dest_port=args.dest_port,
        pps=args.pps,
        bps=args.bps,
        log_file=args.log_file
    )

if __name__ == "__main__":
    main()
