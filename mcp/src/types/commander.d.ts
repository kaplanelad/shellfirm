declare module 'commander' {
  export interface ProgramOptions {
    challenge?: string;
    severity?: string;
    propagateEnv?: string;
  }

  export interface Program {
    name(name: string): Program;
    description(text: string): Program;
    option(flags: string, _desc?: string, _def?: string | boolean | number): Program;
    parse(_argv?: readonly string[]): Program;
    opts(): ProgramOptions;
  }

  export const program: Program;
}


