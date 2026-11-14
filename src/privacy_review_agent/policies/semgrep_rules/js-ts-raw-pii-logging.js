// ruleid: js-ts-raw-pii-logging
console.log(user.email);
// ruleid: js-ts-raw-pii-logging
console.info(`login ${user.email}`);
// ruleid: js-ts-raw-pii-logging
console.warn("email=" + user.email);
const msg = user.phone;
// ruleid: js-ts-raw-pii-logging
logger.error(msg);
// ruleid: js-ts-raw-pii-logging
console.log(
  user.email
);
// ruleid: js-ts-raw-pii-logging
console.log(req.body);
// ruleid: js-ts-raw-pii-logging
logger.info(request.headers);
// ok: js-ts-raw-pii-logging
console.log(redact(user.email));
// ok: js-ts-raw-pii-logging
console.log(util.mask(user.email));
// ok: js-ts-raw-pii-logging
console.log(request_id);
// ok: js-ts-raw-pii-logging
console.info("user email not found");
// ok: js-ts-raw-pii-logging
save(user.email);
// ok: js-ts-raw-pii-logging
// user email must never be logged
console.log("done");
