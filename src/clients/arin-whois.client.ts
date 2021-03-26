import axios from 'axios';

export type ArinWhoisResult = {
  net: {
    startAddress: {
      $: string;
    };
    endAddress: {
      $: string;
    };
  };
};

export class ArinWhoisClient {
  private axios;

  constructor() {
    this.axios = axios.create({
      baseURL: 'https://whois.arin.net',
      timeout: 5000,
    });
  }

  async ownersOf(ips: string[]): Promise<ArinWhoisResult[]> {
    return Promise.all(
      ips.map(async ip => {
        const { data } = await this.axios.get<ArinWhoisResult>(`/rest/ip/${ip}.json`);
        return data;
      }),
    );
  }
}
