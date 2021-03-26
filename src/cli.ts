#! /usr/bin/env node --http-parser=legacy
import command from 'commander';
import { log as printToStdOut } from 'console';
import ejs from 'ejs';
import moment from 'moment';
import path from 'path';
import { createLogger, format, transports } from 'winston';
import { Digg } from './digg';

// eslint-disable-next-line @typescript-eslint/ban-types
async function renderTemplate<T extends Object>(templateName: string, data: T) {
  const filePath = path.join(__dirname, `templates/${templateName}.ejs`);
  const output = await ejs.renderFile(filePath, {
    ...data,
    moment,
  });
  printToStdOut(output);
}

command
  .version('0.0.1')
  .arguments('<domainOrUrl>')
  .action(async domainOrUrl => {
    const logger = createLogger({
      transports: [
        new transports.Console({
          level: 'info',
          format: format.combine(format.colorize(), format.prettyPrint(), format.splat(), format.simple()),
        }),
      ],
    });

    printToStdOut(`Diggin' into ${domainOrUrl}\n`);

    const digg = new Digg({ domainOrUrl })
      .on('txt', async txt => {
        await renderTemplate('dns.txt', { txt });
      })
      .on('a', async a => {
        await renderTemplate('dns.a', { a });
      })
      .on('cname', async cname => {
        await renderTemplate('dns.cname', { cname });
      })
      .on('mx', async mx => {
        await renderTemplate('dns.mx', { mx });
      })
      .on('whois', async whois => {
        await renderTemplate('whois', whois);
      })
      .on('arin', async arin => {
        await renderTemplate('arin', {
          results: arin,
        });
      })
      .on('error', error => {
        logger.error(error);
      });

    await digg.findAll();
  })
  .parse(process.argv);
