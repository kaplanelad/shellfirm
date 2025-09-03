// Command validation request interface
export interface ValidateCommandRequest {
  command: string;
}

// Command validation response interface
export interface ValidateCommandResponse {
  safe: boolean;
  message: string;
  pattern?: string;
}

// Allowed challenge types for the MCP browser challenge system (flag-supported)
export type ChallengeType = 'confirm' | 'math' | 'word' | 'block';

