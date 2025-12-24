from capture import capture_packets

if __name__ == "__main__":
    print("Starting Network Traffic Analyzer...")
    packets = capture_packets(5)
    print(f"Captured {len(packets)} packets")
