// ruleid: js-ts-raw-pii-logging
console.log(user.email);
// ruleid: js-ts-raw-pii-logging
console.info(`login ${user.email}`);
const contact: string = req.body;
// ruleid: js-ts-raw-pii-logging
logger.error(contact);
// ruleid: js-ts-raw-pii-logging
console.warn(
  request.headers
);
// ok: js-ts-raw-pii-logging
console.log(tokenize(user.token));
// ok: js-ts-raw-pii-logging
logger.info(util.hash(user.ssn));
// ok: js-ts-raw-pii-logging
console.debug(frame_rate);
// ok: js-ts-raw-pii-logging
console.warn("user email not found");
// ok: js-ts-raw-pii-logging
store(user.email);
