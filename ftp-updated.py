import subprocess
import re
import requests
import time
from collections import Counter

def scan_wifi_networks():
    """
    Uses the netsh command to scan for WiFi networks on Windows.
    Returns the raw output as a string.
    """
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Error: Unable to scan WiFi networks. Check your permissions.")
        return None
    return result.stdout

def parse_networks(scan_output):
    """
    Parses the netsh scan output and returns a dictionary mapping SSIDs to
    a list of detail dictionaries containing BSSID, Signal, Channel,
    Authentication, Encryption, and RadioType.
    """
    networks = {}
    current_ssid = None
    current_details = None

    for line in scan_output.splitlines():
        line = line.strip()

        # Detect SSID lines (e.g., "SSID 1 : MyNetwork")
        ssid_match = re.match(r"SSID\s+\d+\s+:\s+(.*)", line)
        if ssid_match:
            current_ssid = ssid_match.group(1)
            networks[current_ssid] = []
            continue

        # Detect BSSID lines (e.g., "BSSID 1 : 00:11:22:33:44:55")
        bssid_match = re.match(r"BSSID\s+\d+\s+:\s+(.*)", line)
        if bssid_match and current_ssid is not None:
            current_details = {"BSSID": bssid_match.group(1)}
            networks[current_ssid].append(current_details)
            continue

        # Capture Signal (e.g., "Signal : 80%")
        signal_match = re.match(r"Signal\s+:\s+(\d+)%", line)
        if signal_match and current_details is not None:
            current_details["Signal"] = int(signal_match.group(1))
            continue

        # Capture Channel (e.g., "Channel : 11")
        channel_match = re.match(r"Channel\s+:\s+(\d+)", line)
        if channel_match and current_details is not None:
            current_details["Channel"] = int(channel_match.group(1))
            continue

        # Capture Authentication (e.g., "Authentication : WPA2-Personal")
        auth_match = re.match(r"Authentication\s+:\s+(.*)", line)
        if auth_match and current_details is not None:
            current_details["Authentication"] = auth_match.group(1)
            continue

        # Capture Encryption (e.g., "Encryption : CCMP")
        encryption_match = re.match(r"Encryption\s+:\s+(.*)", line)
        if encryption_match and current_details is not None:
            current_details["Encryption"] = encryption_match.group(1)
            continue

        # Capture Radio Type (e.g., "Radio type : 802.11n")
        radio_match = re.match(r"Radio type\s+:\s+(.*)", line)
        if radio_match and current_details is not None:
            current_details["RadioType"] = radio_match.group(1)
            continue

    return networks

def get_mac_vendor(mac):
    """
    Returns a vendor string based on the MAC address's OUI.
    Update the vendor_mapping with your expected OUIs.
    """
    vendor_mapping = {
        "80:95:62": "ExpectedVendor",  # Replace with your expected vendor for legitimate APs
        "34:b4:72": "OtherVendor",     # For example, flag if you don't expect this vendor
        # Add additional OUIs as needed.
    }
    oui = ":".join(mac.split(":")[:3]).lower()
    return vendor_mapping.get(oui, "Unknown")

def check_vendor(detail, expected_vendor="ExpectedVendor"):
    """
    Checks if the MAC vendor for a given network detail matches the expected vendor.
    Returns a tuple: (True/False, detected_vendor).
    """
    vendor = get_mac_vendor(detail.get("BSSID", ""))
    if vendor != expected_vendor:
        return False, vendor
    return True, vendor

def detect_captive_portal(test_url="http://www.gstatic.com/generate_204", timeout=5):
    """
    Performs a captive portal test by requesting a URL that should return a 204 status.
    Returns a tuple: (True if a captive portal is detected, HTTP status code).
    """
    try:
        response = requests.get(test_url, timeout=timeout)
        if response.status_code != 204:
            return True, response.status_code
        return False, response.status_code
    except Exception as e:
        print("Error during captive portal detection:", e)
        return None, None

def connect_and_test_captive_portal(ssid, test_url="http://www.gstatic.com/generate_204", timeout=5):
    """
    Attempts to connect to the given SSID (which must have a pre-existing profile)
    and then tests for a captive portal.
    Returns a tuple: (True if captive portal is detected, HTTP status code).
    Note: This function will change your active network connection.
    """
    print(f"\nAttempting to connect to '{ssid}' for captive portal testing...")
    connect_command = f'netsh wlan connect name="{ssid}"'
    result = subprocess.run(connect_command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to connect to {ssid}. Skipping captive portal test for this network.")
        return None, None
    print("Connected. Waiting for connection to stabilize...")
    time.sleep(10)  # Adjust delay as needed for your environment
    portal_detected, status = detect_captive_portal(test_url, timeout)
    return portal_detected, status

def detect_spoofing(networks, baseline, expected_vendor="ExpectedVendor"):
    """
    Compares the scanned network details to a baseline of known configurations.
    Flags potential spoofing when:
      - A BSSID is not in the expected baseline.
      - There are mismatches in Authentication, Encryption, or Channel.
      - The MAC vendor does not match the expected vendor.
    Additionally, for each SSID with multiple APs, it computes the most common (ordinary)
    radio type and flags any AP that does not match it.
    
    Returns a dictionary of alerts per SSID.
    """
    alerts = {}

    # Baseline and per-detail checks.
    for ssid, details_list in networks.items():
        if ssid in baseline:
            expected_details = baseline[ssid]
            expected_bssids = {entry["BSSID"] for entry in expected_details}
            for detail in details_list:
                issues = []
                bssid = detail.get("BSSID")
                # Check if BSSID is known.
                if bssid not in expected_bssids:
                    issues.append(f"Unknown BSSID: {bssid}")
                # Check expected Authentication, Encryption, and Channel.
                for key in ["Authentication", "Encryption", "Channel"]:
                    expected_values = {entry.get(key) for entry in expected_details}
                    if detail.get(key) not in expected_values:
                        issues.append(f"Unexpected {key}: {detail.get(key)} (expected one of {expected_values})")
                # Check MAC vendor.
                vendor_ok, vendor = check_vendor(detail, expected_vendor)
                if not vendor_ok:
                    issues.append(f"MAC Vendor mismatch: {vendor} (expected {expected_vendor})")
                if issues:
                    alerts.setdefault(ssid, []).append({
                        "detail": detail,
                        "issues": issues
                    })
        else:
            # Flag SSIDs not in the trusted baseline.
            alerts.setdefault(ssid, []).append({
                "detail": None,
                "issues": [f"SSID '{ssid}' not in baseline; cannot verify authenticity."]
            })

    # Additional radio type outlier check per SSID.
    for ssid, details_list in networks.items():
        # Only perform if multiple AP entries exist.
        if len(details_list) > 1:
            radio_types = [d.get("RadioType") for d in details_list if d.get("RadioType")]
            if radio_types:
                common_radio = Counter(radio_types).most_common(1)[0][0]
                for detail in details_list:
                    rt = detail.get("RadioType")
                    if rt and rt != common_radio:
                        # Append radio type issue to the alert for this AP.
                        found = False
                        for alert in alerts.get(ssid, []):
                            if alert.get("detail", {}).get("BSSID") == detail.get("BSSID"):
                                alert["issues"].append(f"Uncommon radio type: {rt} (common is {common_radio})")
                                found = True
                                break
                        if not found:
                            alerts.setdefault(ssid, []).append({
                                "detail": detail,
                                "issues": [f"Uncommon radio type: {rt} (common is {common_radio})"]
                            })
    return alerts

def main():
    # Update baseline data with your trusted network configurations.
    known_networks = {
        "KEAN_GUEST": [
            {
                "BSSID": "34:b4:72:63:ef:5b",
                "Channel": 1,
                "Authentication": "WPA2-Personal",
                "Encryption": "CCMP",
                "RadioType": "802.11n"
            }
        ],
        "eduroam": [
            {
                "BSSID": "80:95:62:99:66:19",
                "Channel": 1,
                "Authentication": "WPA2-Enterprise",
                "Encryption": "CCMP",
                "RadioType": "802.11n"
            }
        ],
        "CougarNet": [
            {
                "BSSID": "80:95:62:99:66:18",
                "Channel": 1,
                "Authentication": "Open",
                "Encryption": "None",
                "RadioType": "802.11g"
            }
        ],
        "KUAIR": [
            {
                "BSSID": "80:95:62:99:66:16",
                "Channel": 1,
                "Authentication": "WPA3-Personal",
                "Encryption": "CCMP",
                "RadioType": "802.11ac"
            }
        ]
        # Add or update additional baseline networks as needed.
    }
    # Set the expected vendor string for legitimate access points.
    expected_vendor = "ExpectedVendor"
    
    print("Scanning for WiFi networks...")
    output = scan_wifi_networks()
    if not output:
        return

    # Save raw scan output to file.
    with open("networks.txt", "w", encoding="utf-8") as f:
        f.write(output)
    
    networks = parse_networks(output)
    print("\nDetected networks:")
    for ssid, details in networks.items():
        print(f"SSID: {ssid}")
        for d in details:
            print(f"  BSSID: {d.get('BSSID')} | Signal: {d.get('Signal', 'N/A')}% | Channel: {d.get('Channel', 'N/A')}")
            print(f"    Authentication: {d.get('Authentication', 'N/A')}, Encryption: {d.get('Encryption', 'N/A')}, RadioType: {d.get('RadioType', 'N/A')}")
    
    # Run spoofing detection (baseline and radio type outlier check).
    alerts = detect_spoofing(networks, known_networks, expected_vendor)
    if alerts:
        print("\nPotential spoofing alerts:")
        for ssid, issues_list in alerts.items():
            print(f"\nSSID: {ssid}")
            for alert in issues_list:
                print(f"  Detail: {alert.get('detail')}")
                for issue in alert.get("issues", []):
                    print(f"    Issue: {issue}")
    else:
        print("\nNo spoofing detected based on baseline and radio type checks.")
    
    # Perform passive captive portal detection on the current connection.
    print("\nPerforming passive captive portal detection on the current connection...")
    portal_detected, status = detect_captive_portal()
    if portal_detected is None:
        print("Could not determine captive portal status.")
    elif portal_detected:
        print(f"Captive portal detected (HTTP status: {status}).")
    else:
        print("No captive portal detected (HTTP status: 204).")
    
    # Optionally, attempt an active captive portal test for any flagged SSID.
    for ssid in alerts.keys():
        user_input = input(f"\nDo you want to attempt an active captive portal test for '{ssid}'? (y/n): ")
        if user_input.strip().lower() == 'y':
            portal_detected, status = connect_and_test_captive_portal(ssid)
            if portal_detected is None:
                print(f"Could not determine captive portal status for {ssid}.")
            elif portal_detected:
                print(f"'{ssid}' appears to have a captive portal (HTTP status: {status}).")
            else:
                print(f"'{ssid}' does not appear to have a captive portal (HTTP status: {status}).")

if __name__ == "__main__":
    main()
