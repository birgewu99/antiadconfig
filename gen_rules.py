        # DST-PORT rules output
        with open("output.txt", "a") as f:
            for rule in self.rules:
                if rule.policy == "REJECT":
                    f.write(f"Dst-Port: {rule.dst_port}\n")
                    f.write(f"Policy: {rule.policy}\n")

        # Proceeds to PROXY rules processing
        # Rest of the implementation...