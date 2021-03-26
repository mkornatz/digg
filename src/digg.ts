import { promises } from 'dns';
import EventEmitter from 'events';
import { uniqBy } from 'lodash';
import { URL } from 'url';
import { ArinWhoisClient } from './clients/arin-whois.client.js';
import { WhoisClient } from './clients/whois.client.js';
import Resolver = promises.Resolver;

export class Digg extends EventEmitter {
  private domain?: string;
  private ip?: string;

  constructor({ domainOrUrl }: { domainOrUrl: string }) {
    super();

    if (this.isUrl(domainOrUrl)) {
      const parsedUrl = new URL(domainOrUrl);
      this.domain = parsedUrl.hostname ?? '';
    } else if (this.isIp(domainOrUrl)) {
      this.ip = domainOrUrl;
    } else {
      this.domain = domainOrUrl;
    }
  }

  private isUrl(domainOrUrl: string) {
    return ['http', 'ftp'].some(scheme => domainOrUrl.startsWith(scheme));
  }

  private isSubdomain(domain: string) {
    return !!domain.match(/^([a-z]+:\/{2})?([\w-]+\.[\w-]+\.\w+)$/);
  }

  private isIp(domainOrIp: string) {
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

  async arin(aRecords: string[]) {
    try {
      const arin = new ArinWhoisClient();
      const arinResults = await arin.ownersOf(aRecords);
      this.emit(
        'arin',
        uniqBy(arinResults, result => `${result.net.startAddress['$']}${result.net.endAddress['$']}`),
      );
    } catch (error) {
      this.emit('error', error);
    }
  }

  async findAll() {
    if (this.ip) {
      return this.arin([this.ip]);
    } else {
      this.on('a', async a => {
        await this.arin(a);
      });
      return Promise.all([this.dns(), this.whois()]);
    }
  }
}
