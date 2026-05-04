function audit(event, fields) {
  console.info(
    JSON.stringify({
      ts: new Date().toISOString(),
      event,
      ...fields
    })
  );
}

function auditError(event, fields) {
  console.error(
    JSON.stringify({
      ts: new Date().toISOString(),
      event,
      level: 'error',
      ...fields
    })
  );
}

module.exports = { audit, auditError };
