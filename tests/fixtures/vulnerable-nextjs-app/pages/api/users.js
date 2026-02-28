// No auth middleware on this API route
export default function handler(req, res) {
  const { search } = req.query;

  // User input rendered unsafely
  const html = `<div>${search}</div>`;

  // dangerouslySetInnerHTML usage with user input
  const rendered = { __html: search };

  // PII logged
  console.log("User request:", req.query.email, req.query.phone);

  res.status(200).json({
    users: [],
    preview: html,
  });
}
