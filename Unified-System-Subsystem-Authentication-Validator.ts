// Unified-System-Subsystem-Authentication-Validator.ts
// SAIA-Class 300 — deterministic subsystem authentication validator.

export interface IdentityClaim {
  claimId: string;
  actorId: string;            // subsystem, engine, or process ID
  providedSignature: string;  // signature provided by actor
  expectedSignature: string;  // signature expected by system
  method: string;             // e.g., "HMAC", "RSA", "ECDSA"
  timestampIso: string;
}

export interface AuthenticationPacket {
  packetId: string;
  engineId: string;
  subsystemId: string;
  claim: IdentityClaim;
  timestampIso: string;
}

export type AuthenticationStatus =
  | "AUTHENTICATED"
  | "SIGNATURE_MISMATCH"
  | "UNSUPPORTED_METHOD"
  | "INVALID_PACKET"
  | "TIMESTAMP_ERROR";

export interface AuthenticationRuling {
  rulingId: string;
  packetId: string;
  status: AuthenticationStatus;
  details: string;
  issuedAtIso: string;
  issuedByEngineId: string;
}

export interface AuthenticationValidatorConfig {
  engineId: string;
  supportedMethods: string[]; // allowed cryptographic methods
}

export class UnifiedSystemSubsystemAuthenticationValidator {
  private readonly config: AuthenticationValidatorConfig;

  constructor(config: AuthenticationValidatorConfig) {
    this.config = config;
  }

  public evaluate(packet: AuthenticationPacket): AuthenticationRuling {
    const status = this.resolveStatus(packet);

    return {
      rulingId: this.generateRulingId(packet),
      packetId: packet.packetId,
      status,
      details: this.describe(status),
      issuedAtIso: new Date().toISOString(),
      issuedByEngineId: this.config.engineId,
    };
  }

  private resolveStatus(packet: AuthenticationPacket): AuthenticationStatus {
    if (!packet.timestampIso || !packet.claim.timestampIso) {
      return "TIMESTAMP_ERROR";
    }

    if (!packet.claim) {
      return "INVALID_PACKET";
    }

    // Check supported cryptographic method
    if (!this.config.supportedMethods.includes(packet.claim.method)) {
      return "UNSUPPORTED_METHOD";
    }

    // Signature validation
    if (packet.claim.providedSignature !== packet.claim.expectedSignature) {
      return "SIGNATURE_MISMATCH";
    }

    return "AUTHENTICATED";
  }

  private describe(status: AuthenticationStatus): string {
    switch (status) {
      case "AUTHENTICATED":
        return "Identity authenticated; signature verified.";
      case "SIGNATURE_MISMATCH":
        return "Signature mismatch; identity claim invalid.";
      case "UNSUPPORTED_METHOD":
        return "Unsupported authentication method.";
      case "INVALID_PACKET":
        return "Authentication packet missing required fields.";
      case "TIMESTAMP_ERROR":
        return "Missing or invalid timestamp.";
    }
  }

  private generateRulingId(packet: AuthenticationPacket): string {
    return `AUTHN-${this.config.engineId}-${packet.packetId}-${Date.now()}`;
  }
}

export const DEFAULT_AUTHENTICATION_VALIDATOR_CONFIG: AuthenticationValidatorConfig = {
  engineId: "Unified-System-Subsystem-Authentication-Validator-Class-300",
  supportedMethods: ["HMAC", "RSA", "ECDSA"],
};
