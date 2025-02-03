#!/usr/bin/env python3

import argparse
import time
import random
import logging
from scapy.all import IP, UDP, TCP, ICMP, GRE, Raw, send

def generate_traffic(dest_ip, protocol, icmp_type, dest_port, pps, bps, tcp_flag, log_file, src_port):
    """
    다양한 프로토콜(TCP, UDP, ICMP, GRE)을 사용해 트래픽을 생성하고 속도를 모니터링
    """
    # 로그 설정
    if log_file:
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
        logging.info(f"{protocol.upper()} 트래픽 생성 시작")
    
    # bps (bits per second)를 바이트 단위로 변환하여 패킷당 크기를 계산함.
    target_packet_size = (bps / pps) / 8  # 목표 패킷 크기 (bytes)

    interval = 1 / pps  # pps에 따른 전송 간격 계산
    total_packets = 0
    start_time = time.time()
    
    print(f"[INFO] {protocol.upper()} 트래픽 생성 시작: {pps} PPS, {bps} bps")
    if dest_port:
        print(f"[INFO] Destination Port: {dest_port}")
    
    try:
        while True:
            # src_port가 지정되어 있으면 사용하고, 없으면 랜덤 선택
            current_src_port = src_port if src_port is not None else random.randint(1, 65535)
            print(f"[DEBUG] Using Source Port: {current_src_port}")
            
            # 프로토콜에 따른 패킷 생성
            if protocol.upper() == "TCP":
                base_packet = IP(dst=dest_ip) / TCP(sport=current_src_port, dport=dest_port, flags=tcp_flag)
            elif protocol.upper() == "UDP":
                base_packet = IP(dst=dest_ip) / UDP(sport=current_src_port, dport=dest_port)
            elif protocol.upper() == "ICMP":
                base_packet = IP(dst=dest_ip) / ICMP(type=icmp_type)
            elif protocol.upper() == "GRE":
                base_packet = IP(dst=dest_ip) / GRE()
            else:
                print(f"[ERROR] 지원하지 않는 프로토콜: {protocol}. TCP, UDP, ICMP, GRE 중 하나를 사용하세요.")
                return
            
            # 패킷 크기 조정: 패킷 헤더의 크기를 감안하여 필요한 패딩 크기를 계산
            payload_size = max(0, int(target_packet_size - len(base_packet)))
            packet = base_packet / Raw(load="X" * payload_size)
            
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
    parser = argparse.ArgumentParser(description="다양한 프로토콜을 지원하는 트래픽 생성기")
    
    # 필수 인자
    parser.add_argument("dest_ip", help="목적지 IP 주소")
    
    # 선택 인자 (요구사항에 따라 옵션명 변경 및 추가)
    parser.add_argument("--protocol", type=str, default="UDP", help="프로토콜 형식 (TCP, UDP, ICMP, GRE)")
    parser.add_argument("--pps", type=int, default=1000, help="트래픽 pps 규모 (기본: 1Kpps)")
    parser.add_argument("--bps", type=int, default=100_000_000, help="트래픽 bps 규모 (기본: 100Mbps)")
    parser.add_argument("--dest_port", type=int, default=80, help="Destination Port (기본: 80, ICMP/GRE에서는 무시됨)")
    parser.add_argument("--icmp-type", type=int, default=8, help="ICMP 타입 (Echo Request: 8, Echo Reply: 0, 기본: 8)")
    parser.add_argument("--tcp-flag", type=str, default="S", help="TCP 플래그 값 (예: S, A, F, R 등, 기본: S)")
    parser.add_argument("--log-file", type=str, help="송신 속도를 기록할 로그 파일 경로")
    parser.add_argument("--src_port", type=int, help="패킷의 source port 지정 (지정하지 않으면 랜덤)")
    parser.add_argument("--Mbps", type=int, help="Mbps 단위를 입력하면, bps로 변환하여 사용합니다.")
    
    args = parser.parse_args()
    
    # --Mbps 옵션이 제공되면 bps 값을 재설정
    if args.Mbps is not None:
        args.bps = args.Mbps * 1_000_000
    
    # 프로토콜에 따라 dest_port 무시 처리
    if args.protocol.upper() in ["ICMP", "GRE"]:
        args.dest_port = None
    
    generate_traffic(
        dest_ip=args.dest_ip,
        protocol=args.protocol,
        icmp_type=args.icmp_type,
        dest_port=args.dest_port,
        pps=args.pps,
        bps=args.bps,
        tcp_flag=args.tcp_flag,
        log_file=args.log_file,
        src_port=args.src_port
    )

if __name__ == "__main__":
    main()
