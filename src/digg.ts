import { promises } from 'dns';
import EventEmitter from 'events';
import { uniqBy } from 'lodash';
import { URL } from 'url';
import { ArinWhoisClient } from './clients/arin-whois.client.js';
import { WhoisClient } from './clients/whois.client.js';
import Resolver = promises.Resolver;

export class Digg extends EventEmitter {
  private domain?: string;
  private apexDomain?: string;
  private ip4s?: string[];

  constructor({ domainOrUrl }: { domainOrUrl: string }) {
    super();

    if (this.isUrl(domainOrUrl)) {
      const parsedUrl = new URL(domainOrUrl);
      this.domain = parsedUrl.hostname ?? '';
    } else if (this.isIp4(domainOrUrl)) {
      this.ip4s = [domainOrUrl];
    } else {
      this.domain = domainOrUrl;
    }

    if (this.domain && this.isSubdomain(this.domain)) {
      this.apexDomain = this.apex(this.domain);
    }
  }

  private isUrl(domainOrUrl: string) {
    return ['http', 'ftp'].some(scheme => domainOrUrl.startsWith(scheme));
  }

  private isSubdomain(domain: string) {
    return !!domain.match(/^([a-z]+:\/{2})?([\w-]+\.[\w-]+\.\w+)$/);
  }

  private apex(domain: string) {
    return domain;
  }

  private isIp4(domainOrIp: string) {
    return domainOrIp.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  }

  async dns() {
    const resolver = new Resolver();

    return Promise.all([
      (async () => {
        if (!this.domain) {
          return;
        }
        try {
          this.emit('a', await resolver.resolve4(this.domain));
        } catch (error) {
          this.emit('error', error);
        }
      })(),
      (async () => {
        if (!this.domain) {
          return;
        }
        try {
          this.emit('txt', await resolver.resolveTxt(this.domain));
        } catch (error) {
          this.emit('error', error);
        }
      })(),
      (async () => {
        if (!this.domain) {
          return;
        }
        try {
          this.emit('mx', await resolver.resolveMx(this.domain));
        } catch (error) {
          this.emit('error', error);
        }
      })(),
      (async () => {
        if (!this.domain || !this.isSubdomain(this.domain)) {
          return;
        }
        try {
          this.emit('cname', await resolver.resolveCname(this.domain));
        } catch (error) {
          this.emit('error', error);
        }
      })(),
    ]);
  }

  async whois() {
    if (this.domain) {
      try {
        const whoisClient = new WhoisClient();
        this.emit('whois', await whoisClient.lookup(this.domain));
      } catch (error) {
        this.emit('error', error);
      }
    }
  }

  async arin(ip4s: string[]) {
    try {
      const arin = new ArinWhoisClient();
      const arinResults = await arin.ownersOf(ip4s);
      this.emit(
        'arin',
        uniqBy(arinResults, result => `${result.net.startAddress['$']}${result.net.endAddress['$']}`),
      );
    } catch (error) {
      this.emit('error', error);
    }
  }

  async findAll() {
    if (this.ip4s) {
      return this.arin(this.ip4s);
    } else {
      this.on('a', async a => {
        await this.arin(a);
      });
      return Promise.all([this.dns(), this.whois()]);
    }
  }
}
