/**
 * Represents a domain verification record containing the domain name and its associated log verifications.
 */
export interface DomainVerification {
  /** The domain name being verified */
  name: string;
  /** Collection of log verification records for this domain */
  logVerifications: LogVerification[];
}

/**
 * Represents a single log verification record with timestamp and validation status.
 */
export interface LogVerification {
  /** Name of the log being verified */
  name: string;
  /** Timestamp when the verification was performed */
  date: Date;
  /** Whether the verification was successful */
  valid: boolean;
}

/**
 * Singleton store for managing domain verification records.
 * Implements a promise queue to ensure sequential processing of operations.
 */
export class DomainVerificationStore {
  private static instance: Promise<DomainVerificationStore> | null = null;
  private verificationsByDomain: Record<string, DomainVerification> = {};
  private queue: Promise<any> = Promise.resolve();

  private constructor() {}

  /**
   * Enqueues an operation to be executed sequentially
   * @param operation - Function to be executed in the queue
   * @returns Promise resolving to the operation result
   */
  private enqueue<T>(operation: () => Promise<T> | T): Promise<T> {
    return (this.queue = this.queue.then(() => operation()));
  }

  /**
   * Gets the singleton instance of DomainVerificationStore
   * @returns Promise resolving to the store instance
   */
  public static async getInstance(): Promise<DomainVerificationStore> {
    if (DomainVerificationStore.instance === null) {
      DomainVerificationStore.instance = (async () => {
        const store = new DomainVerificationStore();
        return store;
      })();
    }
    return DomainVerificationStore.instance;
  }

  /**
   * Reports a new log verification for a domain
   * @param domainName - The domain name to report verification for
   * @param logName - Name of the log being verified
   * @param valid - Whether the verification was successful
   * @returns Promise that resolves when the operation is complete
   */
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
    });
  }

  /**
   * Removes all verification records for a domain
   * @param domainName - The domain name to clear verifications for
   * @returns Promise that resolves when the operation is complete
   */
  public clearVerificationForDomain(domainName: string): Promise<void> {
    return this.enqueue(() => {
      delete this.verificationsByDomain[domainName];
    });
  }

  /**
   * Retrieves verification records for a domain
   * @param domainName - The domain name to get verifications for
   * @returns Promise resolving to the domain verification record or undefined if not found
   */
  public verificationForDomain(
    domainName: string,
  ): Promise<DomainVerification | undefined> {
    return this.enqueue(() => {
      const verification = this.verificationsByDomain[domainName];
      return verification ? structuredClone(verification) : undefined;
    });
  }
}
