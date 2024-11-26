export interface DomainVerification {
  name: string;
  logVerifications: LogVerification[];
}

export interface LogVerification {
  name: string;
  date: Date;
  valid: boolean;
}

export class DomainVerificationStore {
  private static instance: Promise<DomainVerificationStore> | null = null;
  private verificationsByDomain: Record<string, DomainVerification> = {};
  private queue: Promise<any> = Promise.resolve();

  private constructor() {}

  private enqueue<T>(operation: () => Promise<T> | T): Promise<T> {
    return (this.queue = this.queue.then(() => operation()));
  }

  public static async getInstance(): Promise<DomainVerificationStore> {
    if (DomainVerificationStore.instance === null) {
      DomainVerificationStore.instance = (async () => {
        const store = new DomainVerificationStore();
        return store;
      })();
    }
    return DomainVerificationStore.instance;
  }

  public reportLogVerification(
    domainName: string,
    logName: string,
    valid: boolean,
  ): Promise<void> {
    return this.enqueue(() => {
      const logVerification: LogVerification = {
        name: logName,
        date: new Date(),
        valid,
      };

      const domainVerification = this.verificationsByDomain[domainName] || {
        name: domainName,
        logVerifications: [],
      };

      domainVerification.logVerifications.push(logVerification);
      this.verificationsByDomain[domainName] = domainVerification;

      console.log("Updated");
    });
  }

  public clearVerificationForDomain(domainName: string): Promise<void> {
    return this.enqueue(() => {
      delete this.verificationsByDomain[domainName];
      console.log("Deleted");
    });
  }

  public verificationForDomain(
    domainName: string,
  ): Promise<DomainVerification | undefined> {
    return this.enqueue(() => {
      const verification = this.verificationsByDomain[domainName];
      console.log("Get");
      return verification ? structuredClone(verification) : undefined;
    });
  }
}
