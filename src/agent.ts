import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType,
} from "forta-agent";

const CONTRACT_ADDRESS = "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b";

const BLACKLISTED_ADDRESSES: string[] = [
  "0xa3fa88658d7f6ceea0288033e85de77d3c02f779",
  "0xdf0635793e91d4f8e7426dbd9ed08471186f428d",
  "0x0498fdd3e4234c1d7ce11dd181634d918675f0ee"
];


export const createFinding = (addressDetected: string): Finding => {
  return Finding.fromObject({
    name: "Compound Detech blacklisted",
    description: `Transactions involving blacklisted address ${addressDetected}`,
    alertId: "BLACKLIST-COMP-FORTA-1",
    severity: FindingSeverity.Critical,
    type: FindingType.Suspicious,
    metadata: {
      address: addressDetected,
    },
  });
};

const handleTransaction: HandleTransaction = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];
  const toAddress = txEvent.to;
  if(toAddress !== CONTRACT_ADDRESS) return findings;
  
  const fromAddress = txEvent.from;
  const isFromBlacklisted = BLACKLISTED_ADDRESSES.includes(fromAddress);

  if (!isFromBlacklisted) {
    return findings;
  }

  findings.push(createFinding(fromAddress));
  return findings;
}

export default {
  handleTransaction
};