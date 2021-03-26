import { camelCase } from 'change-case';
import { decode } from 'html-entities';
import util from 'util';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const whois = require('whois');

const lookup = util.promisify(whois.lookup);
const DELIMITER = ':';

/**
 * The result of a WHOIS lookup. This can be either a single object of registration data,
 * or an array of multiple registration data paired with their originating server.
 */
export type WhoisResult = ResultArrayElement[] | RegistrationData;

interface ResultArrayElement {
  server: string;
  data: RegistrationData;
}

interface RegistrationData {
  domainName?: string;
  registryDomainId?: string;
  registrarWhoisServer?: string;
  registrarUrl?: string;
  updatedDate?: string;
  creationDate?: string;
  registrarRegistrationExpirationDate?: string;
  registrar?: string;
  registrarIanaId?: string;
  registrarAbuseContactEmail?: string;
  registrarAbuseContactPhone?: string;
  domainStatus?: string;
  registrantName?: string;
  registrantOrganization?: string;
  registrantStreet?: string;
  registrantCity?: string;
  registrantStateProvince?: string;
  registrantPostalCode?: string;
  registrantCountry?: string;
  registrantPhone?: string;
  registrantEmail?: string;
  adminName?: string;
  adminOrganization?: string;
  adminStreet?: string;
  adminCity?: string;
  adminStateProvince?: string;
  adminPostalCode?: string;
  adminCountry?: string;
  adminPhone?: string;
  adminEmail?: string;
  techName?: string;
  techOrganization?: string;
  techStreet?: string;
  techCity?: string;
  techStateProvince?: string;
  techPostalCode?: string;
  techCountry?: string;
  techPhone?: string;
  techEmail?: string;
  nameServer?: string;
  dnssec?: string;
  urlOfTheIcannWhoisDataProblemReportingSystem?: string;
  lastUpdateOfWhoisDatabase?: string;
}

interface WhoisOptions {
  /** WHOIS server */
  server?: string | Endpoint;
  /** number of times to follow redirects */
  follow?: number;
  /** in milliseconds */
  timeout?: number;
  verbose?: boolean;
  /** bind to a local IP address */
  bind?: string;
  proxy?: string | SocksProxy;
}

interface Endpoint {
  host: string;
  port: number;
}

interface SocksProxy extends Endpoint {
  type: SocksProtocolVersion;
}

type SocksProtocolVersion = 4 | 5;

export class WhoisClient {
  async lookup(domain: string, options: WhoisOptions = {}): Promise<WhoisResult> {
    const result: string = await lookup(domain, options);
    return this.parseLookupResult(result);
  }

  private getCommonDelimiterForm(rawData: string, delimiter: string) {
    const delimiterPattern = new RegExp(delimiter + '\\S+', 'g');
    const delimiterWSpacePattern = new RegExp(delimiter + ' ', 'g');
    const delimiterMatches = rawData.match(delimiterPattern) || [];
    const delimiterWSpaceMatches = rawData.match(delimiterWSpacePattern) || [];

    if (delimiterMatches.length > delimiterWSpaceMatches.length) {
      return delimiter;
    }
    return delimiter + ' ';
  }

  private parseLookupResult(rawData: string) {
    const result: WhoisResult = {};

    rawData = decode(rawData);
    rawData = rawData.replace(/:\s*\r\n/g, ': ');
    const lines = rawData.split('\n');

    const delimiter = this.getCommonDelimiterForm(rawData, DELIMITER);

    lines.forEach(line => {
      line = line.trim();

      // colon space because that's the standard delimiter - not ':' as that's used in eg, http links
      if (line && line.includes(delimiter)) {
        const lineParts = line.split(DELIMITER);

        // 'Greater than' since lines often have more than one colon, eg values with URLs
        if (lineParts.length >= 2) {
          const key = camelCase(lineParts[0]),
            value = lineParts
              .splice(1)
              .join(DELIMITER)
              .trim();

          Object.assign(result, { [key]: value });
        }
      }
    });

    return result;
  }
}
